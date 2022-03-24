# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
import logging
import os
import re
import codecs
import libconf
from tempfile import TemporaryDirectory

from Crypto import Random

from swugenerator.SWUFile import swufile
from swugenerator.artifact import Artifact


class SWUGenerator:
    def __init__(self, template, out, confvars, dirs, crypt, aeskey, firstiv):
        self.swdescription = template
        self.artifacts = []
        self.out = open(out, 'wb')
        self.artifactory = dirs
        self.cpiofile = swufile(self.out)
        self.vars = confvars
        self.lines = []
        self.conf = {}
        self.filelist = []
        self.temp = TemporaryDirectory()
        self.signtool = crypt
        self.aeskey = aeskey
        self.aesiv = firstiv

    @staticmethod
    def generate_iv():
        return Random.get_random_bytes(16).hex()

    def _read_swdesc(self):
        with codecs.open(self.swdescription, 'r') as f:
            self.lines = f.readlines()
            f.close()

    def close(self):
        self.cpiofile.close()
        self.out.close()

    def process_entry(self, entry):
        if 'filename' not in entry:
            return
        new = None
        for image in self.artifacts:
            if image.filename == entry['filename']:
                new = image
                break
        if not new:
            print("New artifact  %s" % entry['filename'])
            new = Artifact(entry['filename'])
            if not new.findfile(self.artifactory):
                logging.critical("Artifact %s not found" % entry['filename'])
                exit(22)

            # Encrypt if required
            if 'encrypted' in entry and self.aeskey:
                iv = self.generate_iv()
                new_path = os.path.join(self.temp.name, entry['filename'])
                new.encrypt(new_path, self.aeskey, iv)
                new.fullfilename = new_path
                # recompute sha256, now for the encrypted file
                new.computesha256()
                entry['ivt'] = iv

            self.artifacts.append(new)
        else:
            print("Artifact  %s already stored" % entry['filename'])
        entry['sha256'] = new.getsha256()

    def find_files_in_swdesc(self, first):
        for n, val in first.items():
            if isinstance(val, libconf.AttrDict):
                self.find_files_in_swdesc(val)
            elif isinstance(val, tuple):
                for t in val:
                    self.find_files_in_swdesc(t)
            else:
                print("%s = %s" % (n, val))
                if n == 'filename':
                    self.filelist.append(first)

    def save_swdescription(self, filename, s):
        fp = codecs.open(filename, 'w', 'utf-8')
        fp.write(s)
        fp.close()

    def process(self):
        self._read_swdesc()
        self._expand_variables()

        swdesc = ""
        for line in self.lines:
            swdesc = swdesc + line
        self.conf = libconf.loads(swdesc)
        self.find_files_in_swdesc(self.conf.software)

        sw = Artifact('sw-description')
        sw.fullfilename = os.path.join(self.temp.name, sw.filename)
        self.artifacts.append(sw)
        if self.signtool:
            sig = Artifact('sw-description.sig')
            sig.fullfilename = os.path.join(self.temp.name, 'sw-description.sig')
            self.artifacts.append(sig)

        for entry in self.filelist:
            self.process_entry(entry)

        swdesc = libconf.dumps(self.conf)

        # libconf mishandle special character if they are part
        # of an attribute. This happens to the embedded-script
        # and the script results to be in just one line.
        # Reinsert \n and \t that was removed by libconf
        swdesc = re.sub(r"\\n", '\n', swdesc)
        swdesc = re.sub(r"\\t", '\t', swdesc)

        self.save_swdescription(os.path.join(self.temp.name, sw.filename), swdesc)

        if self.signtool:
            sw_desc_in = os.path.join(self.temp.name, sw.filename)
            sw_desc_out = os.path.join(self.temp.name, 'sw-description.sig')
            self.signtool.prepare_cmd(sw_desc_in, sw_desc_out)
            self.signtool.sign()

        for artifact in self.artifacts:
            self.cpiofile.addartifacttoswu(artifact.fullfilename)

    def _expand_variables(self):
        write_lines = []
        for line in self.lines:
            while True:
                m = re.match(
                    r"^(?P<before_placeholder>.+)@@(?P<variable_name>\w+)@@(?P<after_placeholder>.+)$", line)
                if m:
                    variable_value = self.vars[m.group('variable_name')]
                    line = m.group('before_placeholder') + variable_value + m.group('after_placeholder')
                    continue
                else:
                    break

            write_lines.append(line)

        self.lines = write_lines

    def setenckey(self, k, iv):
        self.aeskey = k
        self.aesiv = iv
