# pylint: disable=C0114,C0116
"""Tests for the extract command"""
import io
import os

import pytest

from swugenerator import main, swu_file

FILES = [("sw-description", b"software = {};"), ("rootfs.img", os.urandom(200001))]


def make_swu(tmp_path, files=None):
    """SWU with the files (name, content), returns its path"""
    srcdir = tmp_path / "src"
    srcdir.mkdir(exist_ok=True)
    out = io.BytesIO()
    cpio = swu_file.SWUFile(out)
    for name, content in files or FILES:
        path = srcdir / name
        path.write_bytes(content)
        cpio.addartifacttoswu(str(path))
    cpio.add_trailer()
    swu = tmp_path / "in.swu"
    swu.write_bytes(out.getvalue())
    return swu


def check_files(outdir, files=None):
    for name, content in files or FILES:
        assert (outdir / name).read_bytes() == content


def test_extract(tmp_path):
    swu = make_swu(tmp_path)
    main.parse_args(["extract", "-i", str(swu), "-d", str(tmp_path / "out")])
    check_files(tmp_path / "out")


def test_extract_into_current_directory(tmp_path, monkeypatch):
    swu = make_swu(tmp_path)
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    main.parse_args(["extract", "-i", str(swu)])
    check_files(workdir)


def test_extract_large_format(tmp_path):
    # the image as a 070704 entry, as written for files of 4 GiB and more
    swu = make_swu(tmp_path)
    data = swu.read_bytes()
    pos = data.index(b"070702", data.index(b"sw-description") + 1)
    swu.write_bytes(data[:pos] + b"070704" + data[pos + 6:])
    main.parse_args(["extract", "-i", str(swu), "-d", str(tmp_path / "out")])
    check_files(tmp_path / "out")


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda data: data[:100000],  # truncated
        lambda data: b"070707" + data[6:],  # not a SWU
        lambda data: data.replace(b"rootfs.img", b"../root.im"),  # escapes
    ],
)
def test_extract_invalid_swu(tmp_path, corrupt, caplog):
    swu = make_swu(tmp_path)
    swu.write_bytes(corrupt(swu.read_bytes()))
    with pytest.raises(SystemExit) as error:
        main.parse_args(["extract", "-i", str(swu), "-d", str(tmp_path / "out")])
    assert error.value.code == 1
    assert "Cannot extract" in caplog.text
    assert not (tmp_path / "root.im").exists()


def test_extract_missing_swu(tmp_path, caplog):
    with pytest.raises(SystemExit):
        main.parse_args(["extract", "-i", str(tmp_path / "missing.swu")])
    assert "Cannot extract" in caplog.text


@pytest.mark.parametrize(
    "options", [["-o", "out.swu"], ["-k", "RSA,key"], ["-t"]]
)
def test_extract_rejects_output_options(tmp_path, options):
    swu = make_swu(tmp_path)
    with pytest.raises(SystemExit) as error:
        main.parse_args(options + ["extract", "-i", str(swu)])
    assert error.value.code == 2


def test_output_is_required_for_the_other_commands():
    for command in (["-s", "sw-description", "create"],
                    ["-k", "RSA,key", "sign", "-i", "in.swu"],
                    ["mender", "-i", "in.swu", "-D", "dev"]):
        with pytest.raises(SystemExit) as error:
            main.parse_args(command)
        assert error.value.code == 2
