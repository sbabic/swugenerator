# SWUGenerator, SWU Package Generator for SWUpdate
#
# Copyright (C) 2026 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
"""Wrap a SWU into a Mender Artifact

A Mender Server delivers updates only as Mender Artifacts (format
version 3). The SWU is put, unchanged, into an artifact as the payload of
type "swu", as "mender-artifact write module-image -T swu" does. SWUpdate's
Mender Suricatta module takes the SWU out of the artifact while it is
downloaded; the SWU keeps its own signature, the artifact is not signed.
"""

import contextlib
import gzip
import hashlib
import io
import json
import logging
import lzma
import os
import tarfile
import tempfile
import time
from pathlib import Path
from typing import BinaryIO, List, Optional, Tuple

import libconf

CPIO_MAGIC = (b"070701", b"070702")
COMPRESSION = {"gzip": ".gz", "xz": ".xz", "none": ""}
PAYLOAD_NAME = "update.swu"
# ustar, with a pax header only for what does not fit, as a SWU of 8 GB
TAR_FORMAT = tarfile.PAX_FORMAT


class InvalidSWU(ValueError):
    """Raised when the input is not a SWU"""


def _compress(data: bytes, method: str) -> bytes:
    if method == "gzip":
        return gzip.compress(data, compresslevel=6, mtime=0)
    if method == "xz":
        return lzma.compress(data, preset=6)
    return data


def _compressed(fileobj: BinaryIO, method: str):
    """Writable stream compressing into fileobj, which is left open"""
    if method == "gzip":
        # no file name and no time stamp in the gzip header
        return gzip.GzipFile(
            filename="", mode="wb", fileobj=fileobj, compresslevel=6, mtime=0
        )
    if method == "xz":
        return lzma.LZMAFile(fileobj, "wb", preset=6)
    return contextlib.nullcontext(fileobj)


class _HashingReader:
    """Reads from a stream and computes the sha256 of what is read"""

    def __init__(self, fileobj: BinaryIO):
        self.fileobj = fileobj
        self.sha256 = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self.fileobj.read(size)
        self.sha256.update(data)
        return data


def _tarinfo(name: str, size: int, mtime: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o644
    info.mtime = mtime
    return info


def _write_tar(
    fileobj: BinaryIO, files: List[Tuple[str, int, BinaryIO]], mtime: int
) -> None:
    """tar archive of (name, size, stream) entries, in this order"""
    with tarfile.open(fileobj=fileobj, mode="w", format=TAR_FORMAT) as tar:
        for name, size, data in files:
            tar.addfile(_tarinfo(name, size, mtime), data)


def _tar(files: List[Tuple[str, bytes]], mtime: int) -> bytes:
    """tar archive of (name, data) entries, in this order"""
    bio = io.BytesIO()
    _write_tar(bio, [(name, len(data), io.BytesIO(data)) for name, data in files], mtime)
    return bio.getvalue()


def read_swu_head(swu: BinaryIO) -> Tuple[str, bytes]:
    """Name and content of the first entry of a SWU (newc or crc cpio)

    Raises:
        InvalidSWU: if the data does not start with a complete cpio entry
    """
    header = swu.read(110)
    if len(header) < 110 or header[:6] not in CPIO_MAGIC:
        raise InvalidSWU("not a SWU (no cpio header)")
    try:
        filesize = int(header[54:62], 16)
        namesize = int(header[94:102], 16)
        checksum = int(header[102:110], 16)
    except ValueError as error:
        raise InvalidSWU("invalid cpio header") from error
    name = swu.read(namesize)
    swu.read((4 - (110 + namesize) % 4) % 4)
    data = swu.read(filesize)
    if len(name) < namesize or len(data) < filesize:
        raise InvalidSWU("the SWU is truncated")
    name = name.rstrip(b"\0").decode(errors="replace")
    # 070702 has a checksum, 070701 has none
    if header[:6] == b"070702" and sum(data) & 0xFFFFFFFF != checksum:
        raise InvalidSWU(f"wrong checksum of {name}")
    return name, data


def swu_version(sw_description: bytes) -> Optional[str]:
    """version in the software block of sw-description (libconfig or JSON)

    Returns None if there is none, or if sw-description cannot be parsed,
    for example because it is encrypted.
    """
    try:
        text = sw_description.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        conf = json.loads(text)
    except ValueError:
        try:
            conf = libconf.loads(text)
        except (libconf.ConfigParseError, ValueError):
            return None
    software = conf.get("software") if isinstance(conf, dict) else None
    version = software.get("version") if isinstance(software, dict) else None
    return version if isinstance(version, str) and version else None


def write_artifact(
    out: BinaryIO,
    swu: BinaryIO,
    name: str,
    device_types: List[str],
    payload_type: str = "swu",
    compression: str = "gzip",
    mtime: Optional[int] = None,
    tmp_dir: Optional[Path] = None,
) -> None:
    # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    """Writes a Mender Artifact (version 3) with the SWU as its payload

    The SWU is streamed: it is read once, and never held in memory.

    Args:
        out (BinaryIO): where the artifact is written
        swu (BinaryIO): the SWU, read from its current position to the end
        name (str): artifact name
        device_types (List[str]): compatible device types
        payload_type (str): payload type, "swu" for SWUpdate
        compression (str): "gzip", "xz" or "none" for header and payload
        mtime (int): time stamp of the entries, default SOURCE_DATE_EPOCH or now
        tmp_dir (Path): directory for the compressed payload, default the system one
    """
    if mtime is None:
        mtime = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    suffix = COMPRESSION[compression]

    version = json.dumps({"format": "mender", "version": 3}).encode()
    header_info = json.dumps(
        {
            "payloads": [{"type": payload_type}],
            "artifact_provides": {"artifact_name": name},
            "artifact_depends": {"device_type": device_types},
        }
    ).encode()
    header_name = "header.tar" + suffix
    header = _compress(
        _tar(
            [
                ("header-info", header_info),
                ("headers/0000/type-info", json.dumps({"type": payload_type}).encode()),
                ("headers/0000/meta-data", b"{}"),
            ],
            mtime,
        ),
        compression,
    )
    start = swu.tell()
    swu_size = swu.seek(0, os.SEEK_END) - start
    swu.seek(start)

    # the outer tar needs the size of the compressed payload before it,
    # so the payload is compressed into a temporary file first
    with tempfile.TemporaryFile(dir=tmp_dir) as data:
        reader = _HashingReader(swu)
        with _compressed(data, compression) as stream:
            _write_tar(stream, [(PAYLOAD_NAME, swu_size, reader)], mtime)
        data_size = data.tell()
        data.seek(0)

        # as written by sha256sum
        manifest = "".join(
            f"{digest}  {fname}\n"
            for fname, digest in sorted(
                [
                    ("version", hashlib.sha256(version).hexdigest()),
                    (header_name, hashlib.sha256(header).hexdigest()),
                    ("data/0000/" + PAYLOAD_NAME, reader.sha256.hexdigest()),
                ]
            )
        ).encode()

        _write_tar(
            out,
            [
                ("version", len(version), io.BytesIO(version)),
                ("manifest", len(manifest), io.BytesIO(manifest)),
                (header_name, len(header), io.BytesIO(header)),
                ("data/0000.tar" + suffix, data_size, data),
            ],
            mtime,
        )


class SWUMender:
    """Wraps a SWU file into a Mender Artifact file"""

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        in_file: Path,
        out_file: Path,
        device_types: List[str],
        name: Optional[str] = None,
        payload_type: str = "swu",
        compression: str = "gzip",
    ):
        self.in_file = Path(in_file)
        self.out_file = Path(out_file)
        self.device_types = device_types
        self.name = name
        self.payload_type = payload_type
        self.compression = compression
        self.tmp_file = self.out_file.with_name(self.out_file.name + ".tmp")

    def process(self) -> None:
        """Writes the artifact

        Raises:
            InvalidSWU: if the input is not a SWU, or no name can be found
        """
        with open(self.in_file, "rb") as swu:
            first, sw_description = read_swu_head(swu)
            if first != "sw-description":
                raise InvalidSWU(f"the first file is {first}, not sw-description")
            name = self.name or swu_version(sw_description)
            if not name:
                raise InvalidSWU(
                    "no version in sw-description (or it is encrypted), "
                    "the artifact name is needed"
                )
            if any(c.isspace() for c in name):
                raise InvalidSWU("the artifact name must not contain spaces")
            swu.seek(0)
            with open(self.tmp_file, "wb") as out:
                write_artifact(
                    out, swu, name, self.device_types, self.payload_type,
                    self.compression, tmp_dir=self.out_file.parent,
                )
        logging.info(
            "%s: artifact %s for %s, %d bytes",
            self.out_file,
            name,
            ", ".join(self.device_types),
            self.tmp_file.stat().st_size,
        )

    def close(self) -> None:
        """Moves the artifact in place"""
        os.replace(self.tmp_file, self.out_file)

    def abort(self) -> None:
        """Drops a partial artifact"""
        if self.tmp_file.exists():
            self.tmp_file.unlink()
