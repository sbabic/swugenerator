# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
#
# This class manages to pack the SWU file
# it has methods to add files to the archive
import os
import stat


class CPIOException(Exception):
    pass


class SWUFile:
    def __init__(self, outfile):
        self.position = 0
        """
        :type outfile: FileIO of bytes
        """
        self.outfile = outfile
        self.position = 0

    def _rawwrite(self, data):
        """
        :type data: bytes
        """
        self.outfile.write(data)
        self.position += len(data)

    def _align(self):
        offset = -(self.position % -4)
        if offset:
            self._rawwrite(b"\x00" * offset)

    def cpiocrc(self, cpio_filename):
        crc = 0
        with open(cpio_filename, "rb") as rd:
            chunk = rd.read(65536)
            while chunk:
                for b in chunk:
                    crc += b
                chunk = rd.read(65536)
        crc = crc & 0xFFFFFFFF
        return crc

    def addartifacttoswu(self, cpio_filename):
        """
        :type cpio_filename: string
        """

        statres = os.stat(cpio_filename)
        size = statres.st_size

        # very common error, so check sooner
        if size > 0xFFFFFFFF:
            raise CPIOException(
                "Too big file size for this CPIO format", statres.st_size
            )

        if not stat.S_ISREG(statres.st_mode) or not size:
            raise CPIOException("File is not a regular file")

        if cpio_filename == b"TRAILER!!!":
            raise CPIOException("Attempt to pass reserved filename", cpio_filename)

        self.write_header(cpio_filename)

        self._align()
        with open(cpio_filename, "rb") as xxx:
            while size:
                chunk = xxx.read(65536)
                if not chunk:
                    break
                self._rawwrite(chunk)
                size -= len(chunk)
        if size:
            raise CPIOException("File was changed while reading", cpio_filename)

    def write_header(self, cpio_filename):
        if cpio_filename != "TRAILER!!!":
            statres = os.stat(cpio_filename)
            crc = self.cpiocrc(cpio_filename)
            base_filename = os.path.basename(cpio_filename)
            fields = [
                statres.st_ino,
                statres.st_mode,
                statres.st_uid,
                statres.st_gid,
                statres.st_nlink,
                0,  # mtime
                statres.st_size,
                os.major(statres.st_dev),
                os.minor(statres.st_dev),
                os.major(statres.st_rdev),
                os.minor(statres.st_rdev),
                # Yes, length including last zero byte
                len(base_filename) + 1,
                # New CRC Format
                #  The ``CRC'' format is mis-named, as it uses a simple checksum and not a
                #  cyclic redundancy check.
                crc,
            ]
        else:
            base_filename = cpio_filename
            fields = [0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, len(base_filename) + 1, 0]

        self._align()
        self._rawwrite(b"070702")
        for i, value in enumerate(fields):
            # UNIX epoch overflow, negative timestamps and so on...
            if (value > 0xFFFFFFFF) or (value < 0):
                raise CPIOException("STOP: value out of range", i, value)
            s = f"{value:08X}"
            self.outfile.write(bytes(s, "ascii"))
            self.position += len(s)

        fn = bytes(base_filename, "ascii") + b"\x00"
        self._rawwrite(fn)

    def close(self):
        self.write_header("TRAILER!!!")
        offset = -(self.position % -512)
        if offset:
            self._rawwrite(b"\x00" * offset)
        self.position = 0
