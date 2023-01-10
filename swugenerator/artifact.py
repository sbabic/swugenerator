# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
import hashlib
import os
import subprocess


class Artifact:
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.newfilename = filename
        self.fullfilename = filename
        self._available = False
        self.sha256 = ""
        self.ivt = ""
        self.size = 0

    def exist(self):
        return os.path.exists(self.filename)

    def getsha256(self):
        m = hashlib.sha256()
        with open(os.path.join(self.fullfilename), "rb") as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                m.update(data)
            f.close()
        self.sha256 = m.hexdigest()
        return self.sha256

    def findfile(self, artifactdirs):
        for libdir in artifactdirs:
            fname = os.path.join(libdir, self.filename)
            if os.path.exists(fname):
                self.fullfilename = fname
                self.sha256 = self.getsha256()
                self.size = os.path.getsize(fname)
                return True
        return False

    def getsize(self):
        return self.size

    def encrypt(self, out, key, iv):
        enc_args = [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-in",
            self.fullfilename,
            "-out",
            out,
        ]
        enc_args += ["-K", key, "-iv", iv, "-nosalt"]
        subprocess.run(enc_args, check=True)
