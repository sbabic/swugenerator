# Copyright (C) 2025 INgo Rah
#
# SPDX-License-Identifier: GPLv3
import logging
from tempfile import TemporaryDirectory
from pathlib import Path

from swugenerator.swu_file import SWUFile

class SWUSigner:
    def __init__(self, in_file, out_file, crypt):
        self.signtool = crypt
        self.fout = open(out_file, "wb")
        self.cpio_out = SWUFile(self.fout)
        self.fin = open(in_file, "rb")
        self.cpio_in = SWUFile(self.fin)
        self.temp = TemporaryDirectory()

    def close(self):
        self.temp.cleanup()
        self.fin.close()
        self.cpio_out.add_trailer()
        self.fout.close()

    def process(self):
        # extract the swu file and get the file list
        artifacts = self.cpio_in.extract(self.temp.name)

        # call signing to generate the sig file
        if self.signtool:
            sw_desc_in = Path(self.temp.name) / artifacts[0]
            sw_desc_out = sw_desc_in.with_suffix(".sig")
            self.signtool.prepare_cmd(sw_desc_in, sw_desc_out)
            self.signtool.sign()
            if artifacts[0] + ".sig" not in artifacts:
                artifacts.insert(1, artifacts[0] + ".sig")
            else:
                logging.info("resigning a signed file")

        for name in artifacts:
            path = Path(self.temp.name) / name
            self.cpio_out.addartifacttoswu(path)

