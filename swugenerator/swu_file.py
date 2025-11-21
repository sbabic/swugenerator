# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
#
# This class manages to pack the SWU file and
# extracts a SWU file with returning the list.
# It has methods to add files to the archive.
import os
import stat


class CPIOException(Exception):
    pass

class MagicException(Exception):
    pass

class FormatException(Exception):
    pass

class SWUFile:
    def __init__(self, file):
        """
        :type file: FileIO of bytes
        """
        self.position = 0
        self.file = file
        self.renumbered_inode_count = 0
        self.artifacts = []
        # for reading
        self.header = None

    def _rawwrite(self, data):
        """
        :type data: bytes
        """
        self.file.write(data)
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
        self.artifacts.append(cpio_filename)

    def next_renumbered_inode(self):
        """Make renumbered inode to be safe on 64 bit file systems.

        Simply counting up inodes is enough since swupdate doesn't preserve hard links.
        """
        self.renumbered_inode_count += 1
        return self.renumbered_inode_count

    def write_header(self, cpio_filename):
        if cpio_filename != "TRAILER!!!":
            statres = os.stat(cpio_filename)
            crc = self.cpiocrc(cpio_filename)
            base_filename = os.path.basename(cpio_filename)
            fields = [
                self.next_renumbered_inode(),
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
            self._rawwrite(bytes(s, "ascii"))

        fn = bytes(base_filename, "ascii") + b"\x00"
        self._rawwrite(fn)

    def add_trailer(self):
        try:
            self.write_header("TRAILER!!!")
            offset = -(self.position % -512)
            if offset:
                self._rawwrite(b"\x00" * offset)
        except PermissionError:
            # the file may have been opened for reading
            # flush shouldn't be called
            logging.info("flush called on read only file")

        self.position = 0

    def _extract_file(self, dir, name):
        c_mode = int(self.header[14:22], 16)
        c_filesize = int(self.header[54:62], 16)
        # Read file data
        filedata = self.file.read(c_filesize)
        pad = (4 - c_filesize % 4) % 4
        self.file.read(pad)
        # Compute output path
        path = os.path.join(dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # check if its really a file
        if c_mode & 0o170000 != 0o040000:
            with open(path, "wb") as out:
                out.write(filedata)
            try:
                # preserve mode
                os.chmod(path, c_mode & 0o7777)
            except Exception:
                pass
        # check CRC
        outcrc = self.cpiocrc(path)
        incrc = int(self.header[102:110], 16)
        if outcrc !=  incrc:
            raise FormatException(
                f"Wrong file crc {incrc} vs. {outcrc}"
            )

    def _extract_next(self, dir):
        # Read fixed-size header (110 bytes for "newc" format)
        self.header = self.file.read(110)
        if len(self.header) < 110:
            raise FormatException(
                f"Unknown or unsupported header format. "
            )
        # Parse fields: all are ASCII hex numbers
        c_magic = self.header[0:6].decode()
        if c_magic != "070702":
            raise MagicException(
                f"Unknown or unsupported CPIO format. Our magic: {c_magic}"
            )
        # Parse fields (hex strings)
        c_namesize = int(self.header[94:102], 16)
        # Read filename (padded to 4 bytes)
        name = self.file.read(c_namesize)
        name = name[:-1].decode()
        if name == "TRAILER!!!":
            # end of archive
            return False
        # Align to 4 bytes
        pad = (4 - (110 + c_namesize) % 4) % 4
        self.file.read(pad)
        self.artifacts.append(name)
        self._extract_file(dir, name)

		# lets continue
        return True

    def extract(self, dir):
        # extract all files from the swu file
        next_file = True
        while next_file:
            next_file = self._extract_next(dir)

        return self.artifacts
