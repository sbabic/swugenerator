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

import gzip
import hashlib
import io
import json
import logging
import lzma
import os
import re
import tarfile
import time
from pathlib import Path
from typing import List, Optional, Tuple

CPIO_MAGIC = (b"070701", b"070702")
COMPRESSION = {"gzip": ".gz", "xz": ".xz", "none": ""}
PAYLOAD_NAME = "update.swu"


class InvalidSWU(ValueError):
    """Raised when the input is not a SWU"""


def _compress(data: bytes, method: str) -> bytes:
    if method == "gzip":
        return gzip.compress(data, compresslevel=6, mtime=0)
    if method == "xz":
        return lzma.compress(data, preset=6)
    return data


def _tar(files: List[Tuple[str, bytes]], mtime: int) -> bytes:
    """ustar archive of (name, data) entries, in this order"""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = mtime
            tar.addfile(info, io.BytesIO(data))
    return bio.getvalue()


def read_swu_head(swu: bytes) -> Tuple[str, bytes]:
    """Name and content of the first entry of a SWU (newc or crc cpio)

    Raises:
        InvalidSWU: if the data does not start with a cpio header
    """
    if len(swu) < 110 or swu[:6] not in CPIO_MAGIC:
        raise InvalidSWU("not a SWU (no cpio header)")
    try:
        filesize = int(swu[54:62], 16)
        namesize = int(swu[94:102], 16)
    except ValueError as error:
        raise InvalidSWU("invalid cpio header") from error
    name = swu[110 : 110 + namesize].rstrip(b"\0").decode(errors="replace")
    start = 110 + namesize
    start += (4 - start % 4) % 4
    return name, swu[start : start + filesize]


def swu_version(sw_description: bytes) -> Optional[str]:
    """version of the software in sw-description (libconfig or JSON)"""
    match = re.search(rb'(?m)^\s*"?version"?\s*[=:]\s*"([^"]+)"', sw_description)
    return match.group(1).decode() if match else None


def make_artifact(
    swu: bytes,
    name: str,
    device_types: List[str],
    payload_type: str = "swu",
    compression: str = "gzip",
    mtime: Optional[int] = None,
) -> bytes:
    """Mender Artifact (version 3) with the SWU as its payload

    Args:
        swu (bytes): the SWU
        name (str): artifact name
        device_types (List[str]): compatible device types
        payload_type (str): payload type, "swu" for SWUpdate
        compression (str): "gzip", "xz" or "none" for header and payload
        mtime (int): time stamp of the entries, default SOURCE_DATE_EPOCH or now

    Returns:
        bytes: the artifact
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
    data = _compress(_tar([(PAYLOAD_NAME, swu)], mtime), compression)

    # as written by sha256sum
    manifest = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {fname}\n"
        for fname, content in sorted(
            [
                ("version", version),
                (header_name, header),
                ("data/0000/" + PAYLOAD_NAME, swu),
            ]
        )
    ).encode()

    return _tar(
        [
            ("version", version),
            ("manifest", manifest),
            (header_name, header),
            ("data/0000.tar" + suffix, data),
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
        swu = self.in_file.read_bytes()
        first, sw_description = read_swu_head(swu)
        if first != "sw-description":
            raise InvalidSWU(f"the first file is {first}, not sw-description")
        name = self.name or swu_version(sw_description)
        if not name:
            raise InvalidSWU("no version in sw-description, the artifact name is needed")
        if any(c.isspace() for c in name):
            raise InvalidSWU("the artifact name must not contain spaces")
        artifact = make_artifact(
            swu, name, self.device_types, self.payload_type, self.compression
        )
        self.tmp_file.write_bytes(artifact)
        logging.info(
            "%s: artifact %s for %s, %d bytes",
            self.out_file,
            name,
            ", ".join(self.device_types),
            len(artifact),
        )

    def close(self) -> None:
        """Moves the artifact in place"""
        os.replace(self.tmp_file, self.out_file)

    def abort(self) -> None:
        """Drops a partial artifact"""
        if self.tmp_file.exists():
            self.tmp_file.unlink()
