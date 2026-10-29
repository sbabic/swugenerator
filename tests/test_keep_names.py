# pylint: disable=C0114,C0116,W0621
"""Tests for --keep-names: encrypted artifacts without the suffix .enc"""
import contextlib
import io
import shutil
import subprocess

import pytest

from swugenerator import main
from swugenerator.swu_file import SWUFile

KEY = "aa" * 32
IV = "bb" * 16
DATA = b"container image\n" * 100

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")


@pytest.fixture()
def workdir(tmp_path):
    (tmp_path / "image.tar").write_bytes(DATA)
    (tmp_path / "aes.key").write_text(f"key={KEY}\niv={IV}\n")
    return tmp_path


def create(workdir, images, keep_names):
    entries = ", ".join(
        '{ filename = "image.tar"; type = "raw"; device = "/dev/null"; %s }'
        % ("encrypted = true;" if encrypted else "")
        for encrypted in images
    )
    (workdir / "sw-description").write_text(
        'software = { version = "1.0"; images: ( %s ); }\n' % entries
    )
    swu = workdir / "out.swu"
    main.parse_args(
        ["-a", str(workdir), "-s", str(workdir / "sw-description"), "-o", str(swu),
         "-K", str(workdir / "aes.key"), "-n"]
        + (["--keep-names"] if keep_names else [])
        + ["create"]
    )
    outdir = workdir / "extracted"
    with open(swu, "rb") as f:
        names = SWUFile(f).extract(str(outdir))
    return names, outdir


def decrypt(path, ivt):
    return subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", KEY, "-iv", ivt, "-in", str(path)],
        check=True, capture_output=True,
    ).stdout


def ivt_of(swdesc):
    return swdesc.split('ivt = "')[1].split('"')[0]


def test_encrypted_artifact_gets_suffix_by_default(workdir):
    names, outdir = create(workdir, [True], keep_names=False)
    assert names == ["sw-description", "image.tar.enc"]
    assert 'filename = "image.tar.enc"' in (outdir / "sw-description").read_text()


def test_keep_names(workdir):
    names, outdir = create(workdir, [True], keep_names=True)
    assert names == ["sw-description", "image.tar"]
    swdesc = (outdir / "sw-description").read_text()
    assert 'filename = "image.tar"' in swdesc
    assert decrypt(outdir / "image.tar", ivt_of(swdesc)) == DATA


def test_keep_names_refuses_plain_and_encrypted_copy(workdir, caplog):
    # both would be stored as image.tar
    with pytest.raises(SystemExit):
        create(workdir, [False, True], keep_names=True)
    assert "do not use --keep-names" in caplog.text
    assert not (workdir / "out.swu").exists()


def test_plain_and_encrypted_copy_without_keep_names(workdir):
    names, outdir = create(workdir, [False, True], keep_names=False)
    assert names == ["sw-description", "image.tar", "image.tar.enc"]
    assert (outdir / "image.tar").read_bytes() == DATA


def test_option_in_help():
    out = io.StringIO()
    with pytest.raises(SystemExit), contextlib.redirect_stdout(out):
        main.parse_args(["-h"])
    assert "--keep-names" in out.getvalue()
