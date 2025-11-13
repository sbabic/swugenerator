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
