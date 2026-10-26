# pylint: disable=C0114,C0116,W0621
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from swugenerator import mender

DATA = Path(__file__).parent / "test_data" / "integration_output"
SWUS = [DATA / "output.swu", DATA / "signed_output.swu"]


def members(data: bytes):
    """(name, content) of the entries of a tar archive, in order"""
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return [(m.name, tar.extractfile(m).read()) for m in tar.getmembers()]


def check_artifact(artifact: bytes, swu: bytes, compression: str):
    """Checks layout and checksums as a Mender client does; returns header-info"""
    suffix = mender.COMPRESSION[compression]
    outer = members(artifact)
    assert [n for n, _ in outer] == [
        "version",
        "manifest",
        "header.tar" + suffix,
        "data/0000.tar" + suffix,
    ]
    files = dict(outer)
    assert json.loads(files["version"]) == {"format": "mender", "version": 3}

    header = members(files["header.tar" + suffix])
    assert [n for n, _ in header] == [
        "header-info",
        "headers/0000/type-info",
        "headers/0000/meta-data",
    ]
    payload = members(files["data/0000.tar" + suffix])
    assert payload == [("update.swu", swu)]

    manifest = {}
    for line in files["manifest"].decode().splitlines():
        digest, name = line.split("  ")
        manifest[name] = digest
    assert manifest == {
        "version": hashlib.sha256(files["version"]).hexdigest(),
        "header.tar" + suffix: hashlib.sha256(files["header.tar" + suffix]).hexdigest(),
        "data/0000/update.swu": hashlib.sha256(swu).hexdigest(),
    }
    return json.loads(dict(header)["header-info"])


@pytest.mark.parametrize("swu_path", SWUS)
@pytest.mark.parametrize("compression", list(mender.COMPRESSION))
def test_wrap_swu(tmp_path, swu_path, compression):
    out = tmp_path / "update.mender"
    wrapper = mender.SWUMender(swu_path, out, ["board-a", "board-b"], "release-2",
                               compression=compression)
    wrapper.process()
    wrapper.close()

    info = check_artifact(out.read_bytes(), swu_path.read_bytes(), compression)
    assert info == {
        "payloads": [{"type": "swu"}],
        "artifact_provides": {"artifact_name": "release-2"},
        "artifact_depends": {"device_type": ["board-a", "board-b"]},
    }
    assert not (tmp_path / "update.mender.tmp").exists()


def test_name_from_sw_description(tmp_path):
    out = tmp_path / "update.mender"
    wrapper = mender.SWUMender(SWUS[0], out, ["board"])
    wrapper.process()
    wrapper.close()
    info = check_artifact(out.read_bytes(), SWUS[0].read_bytes(), "gzip")
    assert info["artifact_provides"]["artifact_name"] == "1.0.0"


def test_payload_type(tmp_path):
    out = tmp_path / "update.mender"
    wrapper = mender.SWUMender(SWUS[0], out, ["board"], "r", payload_type="swupdate")
    wrapper.process()
    wrapper.close()
    files = dict(members(out.read_bytes()))
    header = dict(members(files["header.tar.gz"]))
    assert json.loads(header["header-info"])["payloads"] == [{"type": "swupdate"}]
    assert json.loads(header["headers/0000/type-info"]) == {"type": "swupdate"}


def artifact(swu: bytes, compression: str) -> bytes:
    out = io.BytesIO()
    mender.write_artifact(out, io.BytesIO(swu), "r", ["board"], compression=compression)
    return out.getvalue()


def test_reproducible(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    swu = SWUS[0].read_bytes()
    for compression in mender.COMPRESSION:
        assert artifact(swu, compression) == artifact(swu, compression)


class ChunkReader(io.BytesIO):
    """Fails if more than a chunk is read at once"""

    def read(self, size=-1):
        assert 0 <= size <= 1 << 20
        return super().read(size)


@pytest.mark.parametrize("compression", list(mender.COMPRESSION))
def test_streamed(tmp_path, compression):
    swu = SWUS[0].read_bytes() + os.urandom(3 << 20)
    out = io.BytesIO()
    mender.write_artifact(out, ChunkReader(swu), "r", ["board"], compression=compression,
                          tmp_dir=tmp_path)
    check_artifact(out.getvalue(), swu, compression)
    assert not list(tmp_path.iterdir())


def cpio(name: bytes, data: bytes) -> bytes:
    """newc cpio entry, enough for read_swu_head()"""
    namez = name + b"\0"
    fields = [1, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(namez), 0]
    hdr = b"070701" + b"".join(b"%08x" % v for v in fields) + namez
    hdr += b"\0" * ((4 - len(hdr) % 4) % 4)
    return hdr + data + b"\0" * ((4 - len(data) % 4) % 4)


@pytest.mark.parametrize(
    "content,error",
    [
        (b"this is not a SWU" * 10, "no cpio header"),
        (cpio(b"rootfs.img", b"data"), "not sw-description"),
        (cpio(b"sw-description", b'software = { description = "x"; };'),
         "no version in sw-description"),
    ],
)
def test_invalid_input(tmp_path, content, error):
    swu = tmp_path / "in.swu"
    swu.write_bytes(content)
    out = tmp_path / "update.mender"
    wrapper = mender.SWUMender(swu, out, ["board"])
    with pytest.raises(mender.InvalidSWU, match=error):
        wrapper.process()
    wrapper.abort()
    assert not out.exists()
    assert not (tmp_path / "update.mender.tmp").exists()


def test_name_with_spaces(tmp_path):
    wrapper = mender.SWUMender(SWUS[0], tmp_path / "u.mender", ["board"], "release 2")
    with pytest.raises(mender.InvalidSWU, match="spaces"):
        wrapper.process()


@pytest.mark.parametrize(
    "sw_description,version",
    [
        (b'software =\n{\n\tversion = "2.1.0";\n};\n', "2.1.0"),
        (b'{\n  "software": {\n    "version": "3.0"\n  }\n}\n', "3.0"),
        (b'software = { description = "no version"; };', None),
    ],
)
def test_swu_version(sw_description, version):
    assert mender.swu_version(sw_description) == version
