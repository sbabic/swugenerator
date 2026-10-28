import io
import os
from dataclasses import dataclass

import pytest

from swugenerator import swu_file


@dataclass
class StatResult:
    st_dev: int = 42
    st_gid: int = 1000
    st_ino: int = 0x111111111
    st_mode: int = 33204
    st_nlink: int = 1
    st_rdev: int = 0
    st_size: int = 4
    st_uid: int = 1000


@pytest.fixture
def next_artifact(tmp_path):
    class ArtifactFactory:
        def __init__(self):
            self.artifact_nr = 0

        def __call__(self):
            artifact_path = tmp_path / f"artifact{self.artifact_nr}.txt"
            with open(artifact_path, "wb") as artifact:
                artifact.write(b"f00d")
            return artifact_path

    return ArtifactFactory()


def test_write_header_renumber_inode(next_artifact):
    virtual_cpio = io.BytesIO()
    virtual_swu_file = swu_file.SWUFile(virtual_cpio)
    artifact0 = next_artifact()
    artifact1 = next_artifact()
    virtual_swu_file.write_header(artifact0)
    virtual_swu_file.write_header(artifact1)
    header = virtual_cpio.getvalue()
    inode0 = header[6:14]
    inode1 = header[130:138]
    assert inode0 == b"00000001"
    assert inode1 == b"00000002"


def test_write_header_64bit_inode(next_artifact, monkeypatch):
    virtual_cpio = io.BytesIO()
    virtual_swu_file = swu_file.SWUFile(virtual_cpio)
    artifact0 = next_artifact()
    monkeypatch.setattr(
        os, "stat", lambda *_args, **_kwargs: StatResult(st_ino = 0xAAAAAAAA12345678)
    )
    virtual_swu_file.write_header(artifact0)
    header = virtual_cpio.getvalue()
    inode0 = header[6:14]
    assert inode0 == b"00000001"


def make_swu(tmp_path, files):
    """SWU with the files (name, content), returns its content"""
    out = io.BytesIO()
    cpio = swu_file.SWUFile(out)
    for name, content in files:
        path = tmp_path / name
        path.write_bytes(content)
        cpio.addartifacttoswu(str(path))
    cpio.add_trailer()
    return out.getvalue()


def test_extract(tmp_path):
    # bigger than a chunk, size not aligned
    files = [("sw-description", b"software = {};"), ("image.bin", os.urandom(200001))]
    swu = make_swu(tmp_path, files)
    outdir = tmp_path / "out"

    assert swu_file.SWUFile(io.BytesIO(swu)).extract(outdir) == [n for n, _ in files]
    for name, content in files:
        assert (outdir / name).read_bytes() == content


def test_extract_truncated(tmp_path):
    swu = make_swu(tmp_path, [("image.bin", os.urandom(200001))])

    with pytest.raises(swu_file.FormatException, match="truncated"):
        swu_file.SWUFile(io.BytesIO(swu[:100000])).extract(tmp_path / "out")


def test_extract_wrong_crc(tmp_path):
    swu = bytearray(make_swu(tmp_path, [("image.bin", b"0123456789")]))
    swu[swu.index(b"0123456789")] ^= 1

    with pytest.raises(swu_file.FormatException, match="crc"):
        swu_file.SWUFile(io.BytesIO(bytes(swu))).extract(tmp_path / "out")


def test_write_header_crc_format(next_artifact):
    virtual_cpio = io.BytesIO()
    swu_file.SWUFile(virtual_cpio).write_header(next_artifact())
    header = virtual_cpio.getvalue()
    assert header[0:6] == b"070702"
    assert header[54:62] == b"00000004"


def test_write_header_large_file(next_artifact, monkeypatch):
    # 4 GiB and more: the upper 32 bits of the size go into c_rdev_maj
    virtual_cpio = io.BytesIO()
    virtual_swu_file = swu_file.SWUFile(virtual_cpio)
    artifact0 = next_artifact()
    monkeypatch.setattr(
        os, "stat", lambda *_args, **_kwargs: StatResult(st_size=0x123456789)
    )
    virtual_swu_file.write_header(artifact0, crc=0)
    header = virtual_cpio.getvalue()
    assert header[0:6] == b"070704"
    assert header[54:62] == b"23456789"
    assert header[78:86] == b"00000001"


def test_extract_large_format(tmp_path):
    files = [("sw-description", b"software = {};"), ("image.bin", os.urandom(1001))]
    swu = make_swu(tmp_path, files)
    # the image as 070704 entry: same size, upper 32 bits are 0
    pos = swu.index(b"070702", swu.index(b"sw-description") + 1)
    swu = swu[:pos] + b"070704" + swu[pos + 6:]
    outdir = tmp_path / "out"

    assert swu_file.SWUFile(io.BytesIO(swu)).extract(outdir) == [n for n, _ in files]
    assert (outdir / "image.bin").read_bytes() == files[1][1]
