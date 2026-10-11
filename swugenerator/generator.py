# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
import codecs
import logging
import os
import re
import shutil
import secrets
import subprocess
import sys
from tempfile import TemporaryDirectory

import libconf

from swugenerator.swu_file import SWUFile
from swugenerator.artifact import Artifact


class SWUGenerator:
    # functions that can be called from sw-description as $name(parms)
    TEMPLATE_FUNCTIONS = ("swupdate_get_sha256", "swupdate_get_size")

    def __init__(
        self,
        template,
        out,
        confvars,
        dirs,
        crypt,
        aeskey,
        firstiv,
        encrypt_swdesc=False,
        no_compress=False,
        no_encrypt=False,
        no_ivt=False,
        no_hash=False
    ):
        self.swdescription = template
        self.artifacts = []
        self.out = open(out, "wb")
        self.artifactory = dirs
        self.cpiofile = SWUFile(self.out)
        self.vars = confvars
        self.lines = []
        self.conf = libconf.AttrDict()
        self.filelist = []
        self.temp = TemporaryDirectory()
        self.signtool = crypt
        self.aeskey = aeskey
        self.aesiv = firstiv
        self.encryptswdesc = encrypt_swdesc
        self.nocompress = no_compress
        self.noencrypt = no_encrypt
        self.noivt = no_ivt
        self.nohash = no_hash

    @staticmethod
    def generate_iv():
        return secrets.token_hex(16)

    def _read_swdesc(self):
        with codecs.open(self.swdescription, "r") as f:
            self.lines = f.readlines()
            f.close()

    def close(self):
        self.temp.cleanup()
        self.cpiofile.add_trailer()
        self.out.close()

    def abort(self):
        # do not leave an incomplete SWU behind
        self.temp.cleanup()
        self.out.close()
        if os.path.exists(self.out.name):
            os.remove(self.out.name)

    def process_compressed_entry(self, entry, cmp, new):
        cmds = {
            "xz": ["xz", "-f", "-k", "-c"],
            "zlib": ["gzip", "-f", "-9", "-n", "-c", "--rsyncable"],
            "zstd": ["zstd", "-z", "-k", "-T0", "-f", "-c"],
        }
        cmd = cmds.get(cmp)
        if not cmd:
            logging.critical("Wrong compression algorithm: %s", cmp)
            sys.exit(1)

        new_path = os.path.join(self.temp.name, new.newfilename) + "." + cmp
        new.newfilename = new.newfilename + "." + cmp

        cmd = cmd + [new.fullfilename]

        try:
            with open(new_path, "wb") as compressed:
                subprocess.run(cmd, stdout=compressed, check=True)
        except (subprocess.CalledProcessError, OSError):
            logging.critical(
                "Cannot compress %s with %s", entry["filename"], cmd
            )
            sys.exit(1)

        new.fullfilename = new_path

    def process_entry(self, entry):
        if "filename" not in entry:
            return
        new = None
        for image in self.artifacts:
            if image.filename == entry["filename"]:
                new = image
                break
        if not new:
            logging.debug("New artifact %s", entry["filename"])
            new = Artifact(entry["filename"])
            if not new.findfile(self.artifactory):
                logging.critical("Artifact %s not found", entry["filename"])
                sys.exit(22)

            new.newfilename = entry["filename"]

            if not self.nocompress and (cmp := entry.get("compressed")):
                self.process_compressed_entry(entry, cmp, new)
            # compression cannot be used with delta, because it has own compressor
            elif ("type" in entry) and entry["type"] == "delta":
                cmd = [
                    "zck",
                    "-u",
                    "--chunk-hash-type",
                    "sha256",
                    "--output",
                    new.fullfilename + ".zck",
                    new.fullfilename,
                ]
                try:
                    subprocess.run(cmd, check=True)
                except (subprocess.CalledProcessError, OSError):
                    logging.critical(
                        "Cannot create ZCK %s with %s", entry["filename"], cmd
                    )
                    sys.exit(1)

                # Now extract header
                cmd = [
                    "zck_read_header",
                    "-v",
                    new.fullfilename + ".zck",
                ]
                try:
                    result = subprocess.run(cmd,
                                            check=True,
                                            capture_output=True,
                                            text=True)
                except (subprocess.CalledProcessError, OSError):
                    logging.critical(
                        "Cannot extract ZCK Header %s with %s", entry["filename"], cmd
                    )
                    sys.exit(1)

                found_header =  re.search(r"Header size: (\d+)", result.stdout)
                if not found_header:
                    logging.critical(
                        "Cannot find ZCK Header size for %s in %s", entry["filename"], cmd
                    )
                    sys.exit(1)
                header_size = int(found_header.group(1))
                zckheaderfile = os.path.join(self.temp.name, new.newfilename)

                with open(zckheaderfile, "wb") as zck:
                    with open(new.fullfilename + ".zck", "rb") as tmpzck:
                        while header_size:
                            chunk = tmpzck.read(header_size)
                            if not chunk:
                                break
                            zck.write(chunk)
                            header_size -= len(chunk)
                new.fullfilename = zckheaderfile

            # Encrypt if required
            if "encrypted" in entry and entry["encrypted"] is True and not self.noencrypt:
                if not self.aeskey:
                    logging.critical(
                        "%s must be encrypted, but no encryption key is given",
                        entry["filename"],
                    )
                    sys.exit(1)
                if self.noivt:
                    if not self.aesiv:
                        logging.critical(
                            "%s must be encrypted, but no initialization vector is given",
                            entry["filename"],
                        )
                        sys.exit(1)
                    iv = self.aesiv
                else:
                    iv = self.generate_iv()

                new.newfilename = new.newfilename + "." + "enc"
                new_path = os.path.join(self.temp.name, new.newfilename)
                new.encrypt(new_path, self.aeskey, iv)
                new.fullfilename = new_path
                # recompute sha256, now for the encrypted file
                entry["ivt"] = iv
                new.ivt = iv

                entry.setdefault("properties", {}) \
                    .update({ "decrypted-size": str(new.getsize()) })

            self.artifacts.append(new)
        else:
            logging.debug("Artifact %s already stored", entry["filename"])

        entry["filename"] = new.newfilename
        if not self.nohash:
            entry["sha256"] = new.getsha256()
        if "encrypted" in entry and entry["encrypted"] is True:
            entry["ivt"] = new.ivt
        if entry.get("compressed") and not self.nocompress:
            entry.setdefault("properties", {}) \
                 .update({ "decompressed-size": str(new.getsize()) })

    def find_files_in_swdesc(self, first):
        for n, val in first.items():
            if isinstance(val, libconf.AttrDict):
                self.find_files_in_swdesc(val)
            elif isinstance(val, tuple):
                for t in val:
                    self.find_files_in_swdesc(t)
            else:
                logging.debug("%s = %s", n, val)
                if n == "filename":
                    self.filelist.append(first)

    def save_swdescription(self, filename, contents):
        with codecs.open(filename, "w", "utf-8") as swd:
            swd.write(contents)

    def process(self):
        self._read_swdesc()
        self._expand_variables()
        self._exec_functions()

        swdesc = ""
        for line in self.lines:
            swdesc = swdesc + line
        self.conf = libconf.loads(swdesc)
        self.find_files_in_swdesc(self.conf.software)

        sw = Artifact("sw-description")
        sw.fullfilename = os.path.join(self.temp.name, sw.filename)
        self.artifacts.append(sw)
        if self.signtool:
            sig = Artifact("sw-description.sig")
            sig.fullfilename = os.path.join(self.temp.name, "sw-description.sig")
            self.artifacts.append(sig)

        for entry in self.filelist:
            self.process_entry(entry)

        swdesc = libconf.dumps(self.conf)

        # libconf mishandle special character if they are part
        # of an attribute. This happens to the embedded-script
        # and the script results to be in just one line.
        # Reinsert \n and \t that was removed by libconf
        swdesc = re.sub(r"\\n", "\n", swdesc)
        swdesc = re.sub(r"\\t", "\t", swdesc)

        swdesc_filename = os.path.join(self.temp.name, sw.filename)
        self.save_swdescription(swdesc_filename, swdesc)

        if self.signtool:
            sw_desc_in = swdesc_filename
            sw_desc_out = os.path.join(self.temp.name, "sw-description.sig")
            self.signtool.prepare_cmd(sw_desc_in, sw_desc_out)
            self.signtool.sign()

        # Encrypt sw-description if required
        if self.encryptswdesc:
            if not self.aeskey:
                logging.critical(
                    "sw-description must be encrypted, but no encryption key is given"
                )
                sys.exit(1)
            if not self.aesiv:
                logging.critical(
                    "sw-description must be encrypted, but no initialization vector is given"
                )
                sys.exit(1)

            iv = self.aesiv
            sw.fullfilename = swdesc_filename
            swdesc_enc = swdesc_filename + ".enc"
            sw.encrypt(swdesc_enc, self.aeskey, iv)
            shutil.copyfile(swdesc_enc, sw.fullfilename)

        for artifact in self.artifacts:
            self.cpiofile.addartifacttoswu(artifact.fullfilename)

    def _expand_variable(self, m):
        name = m.group("variable_name")
        if name not in self.vars:
            logging.critical("Variable %s in sw-description is not defined", name)
            sys.exit(1)
        return str(self.vars[name])

    def _expand_variables(self):
        variable = re.compile(r"@@(?P<variable_name>\w+)@@")
        write_lines = []
        for line in self.lines:
            # values can contain further variables: without a loop between
            # them, they are all expanded after len(self.vars) passes
            for _ in range(len(self.vars) + 1):
                line, expanded = variable.subn(self._expand_variable, line)
                if not expanded:
                    break
            else:
                logging.critical(
                    "Recursive variable definition in sw-description: %s",
                    line.strip(),
                )
                sys.exit(1)
            write_lines.append(line)
        self.lines = write_lines

    def _call_function(self, m):
        name = m.group("function_name")
        if name not in self.TEMPLATE_FUNCTIONS:
            logging.critical("Unknown function %s in sw-description", name)
            sys.exit(1)
        ret = getattr(self, name)(m.group("parms"))
        if ret is None:
            logging.critical(
                "%s(%s) failed: artifact not found", name, m.group("parms")
            )
            sys.exit(1)
        return ret

    def _exec_functions(self):
        # parameters end at the first ')', so other parentheses
        # on the same line are not taken as part of them
        function = re.compile(r"\$(?P<function_name>\w+)\((?P<parms>[^)]+)\)")
        self.lines = [function.sub(self._call_function, line) for line in self.lines]

    def setenckey(self, k, iv):
        self.aeskey = k
        self.aesiv = iv

    def swupdate_get_sha256(self, filename):
        a = Artifact(filename)
        if a.findfile(self.artifactory):
            return a.getsha256()

    def swupdate_get_size(self, filename):
        a = Artifact(filename)
        if a.findfile(self.artifactory):
            return str(a.getsize())
        return "0"
