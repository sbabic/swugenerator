# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
import logging
import os
import shutil
import re
import codecs
import libconf
import secrets
import subprocess
from tempfile import TemporaryDirectory

from swugenerator.SWUFile import swufile
from swugenerator.artifact import Artifact


class SWUGenerator:
    def __init__(self, template, out, confvars, dirs, crypt, aeskey, firstiv, encrypt_swdesc=False, no_compress=False, no_encrypt=False, no_ivt=False):
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
        self.encryptswdesc = encrypt_swdesc
        self.nocompress = no_compress
        self.noencrypt = no_encrypt
        self.noivt = no_ivt

    @staticmethod
    def generate_iv():
        return secrets.token_hex(16)

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
            logging.debug("New artifact  %s" % entry['filename'])
            new = Artifact(entry['filename'])
            if not new.findfile(self.artifactory):
                logging.critical("Artifact %s not found" % entry['filename'])
                exit(22)

            new.newfilename = entry['filename']

            if 'compressed' in entry and not self.nocompress:
                cmp = entry['compressed']
                if cmp == True:
                    cmp = 'zlib'
                if cmp != 'zlib' and cmp != 'zstd':
                    logging.critical("Wrong compression algorithm: %s" % cmp)
                    exit(1)

                new_path = os.path.join(self.temp.name, new.newfilename) + '.' + cmp
                new.newfilename = new.newfilename + '.' + cmp
                if cmp == 'zlib':
                    cmd = ['gzip', '-f', '-9', '-n', '-c', '--rsyncable', new.fullfilename, '>', new_path]
                else:
                    cmd = ['zstd', '-z', '-k', '-T0', '-c', new.fullfilename, '>', new_path]

                try:
                    subprocess.run(' '.join(cmd), shell=True, check=True, text=True)
                except:
                    logging.critical('Cannot compress %s with %s' % (entry['filename'], cmd))
                    exit(1)

                new.fullfilename = new_path

            # Encrypt if required
            if 'encrypted' in entry and not self.noencrypt:
                if not self.aeskey:
                    logging.critical("%s must be encrypted, but no encryption key is given" % entry['filename'] )
                if self.noivt:
                    iv = self.aesiv
                else:
                    iv = self.generate_iv()

                new.newfilename = new.newfilename + '.' + 'enc'
                new_path = os.path.join(self.temp.name, new.newfilename)
                new.encrypt(new_path, self.aeskey, iv)
                new.fullfilename = new_path
                # recompute sha256, now for the encrypted file
                entry['ivt'] = iv
                new.ivt = iv

            self.artifacts.append(new)
        else:
            logging.debug("Artifact  %s already stored" % entry['filename'])

        entry['filename'] = new.newfilename
        entry['sha256'] = new.getsha256()
        entry['ivt'] = new.ivt

    def find_files_in_swdesc(self, first):
        for n, val in first.items():
            if isinstance(val, libconf.AttrDict):
                self.find_files_in_swdesc(val)
            elif isinstance(val, tuple):
                for t in val:
                    self.find_files_in_swdesc(t)
            else:
                logging.debug("%s = %s" % (n, val))
                if n == 'filename':
                    self.filelist.append(first)

    def save_swdescription(self, filename, s):
        fp = codecs.open(filename, 'w', 'utf-8')
        fp.write(s)
        fp.close()

    def process(self):
        self._read_swdesc()
        self._expand_variables()
        self._exec_functions()

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

        # Encrypt sw-description if required
        if self.aeskey and self.encryptswdesc:
            iv = self.aesiv
            sw_desc_plain  = os.path.join(self.temp.name, 'sw-description.plain')
            sw_desc_enc    = os.path.join(self.temp.name, 'sw-description.enc')
            shutil.copyfile(sw.fullfilename, sw_desc_plain)
            sw.encrypt(sw_desc_enc, self.aeskey, iv)
            shutil.copyfile(sw_desc_enc, sw.fullfilename)
            
        if self.signtool:       
            sw_desc_in =  os.path.join(self.temp.name, 'sw-description.plain' 
                                                if self.aeskey and self.encryptswdesc else 'sw-description')
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

    def _exec_functions(self):
        import re
        for index, line in enumerate(self.lines):
            m = re.match(
                r"^(?P<before_placeholder>.+)\$(?P<function_name>\w+)\((?P<parms>.+)\)(?P<after_placeholder>.+)$",
                line)
            if m:
                fun = "self." + m.group('function_name') + "(\"" + m.group('parms') + "\")"
                ret = eval(fun)
                line = m.group('before_placeholder') + ret + m.group('after_placeholder') + "\n"
                self.lines[index] = line

    def setenckey(self, k, iv):
        self.aeskey = k
        self.aesiv = iv

    def swupdate_get_sha256(self, filename):
        a = Artifact(filename)
        return a.computesha256()

    def swupdate_get_size(self, filename):
        a = Artifact(filename)
        if a.findfile(self.artifactory):
            return str(a.getsize())
        return "0"
