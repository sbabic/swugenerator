# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
import copy
import logging
import subprocess
import sys


class SWUSign:
    def __init__(self):
        self.type = None
        self.key = None
        self.cert = None
        self.cmd = None
        self.passin = None
        self.certfile = None
        self.signcmd = []

    def get_passwd_file_args(self):
        passwd_args = []
        if self.passin:
            passwd_args = ["-passin", f"file:{self.passin}"]
        return passwd_args

    def set_password_file(self, passin):
        self.passin = passin

    def get_certfile_args(self):
        certfile_args = []
        if self.certfile:
            certfile_args = ["-certfile", self.certfile]
        return certfile_args

    def set_certfile(self, certfile):
        self.certfile = certfile

    def sign(self):
        try:
            subprocess.run(" ".join(self.signcmd), shell=True, check=True, text=True)
        except subprocess.CalledProcessError:
            logging.critical(
                "SWU cannot be signed, signing command was %s", self.signcmd
            )
            sys.exit(1)


class SWUSignCMS(SWUSign):
    def __init__(self, key, cert, passin, certfile):
        super().__init__()
        self.type = "CMS"
        self.key = key
        self.cert = cert
        self.passin = passin
        self.certfile = certfile

    def prepare_cmd(self, sw_desc_in, sw_desc_sig):
        self.signcmd = [
            "openssl",
            "cms",
            "-sign",
            "-in",
            sw_desc_in,
            "-out",
            sw_desc_sig,
            "-signer",
            self.cert,
        ]
        self.signcmd += [
            "-inkey",
            self.key,
            "-outform",
            "DER",
            "-nosmimecap",
            "-binary",
        ]
        self.signcmd += self.get_passwd_file_args()
        self.signcmd += self.get_certfile_args()


class SWUSignRSA(SWUSign):
    def __init__(self, key, passin):
        super().__init__()
        self.type = "RSA"
        self.key = key
        self.passin = passin

    def prepare_cmd(self, sw_desc_in, sw_desc_sig):
        self.signcmd = (
            ["openssl", "dgst", "-sha256", "-sign", self.key]
            + self.get_passwd_file_args()
            + ["-out", sw_desc_sig, sw_desc_in]
        )


class SWUSignCustom(SWUSign):
    def __init__(self, cmd):
        super().__init__()
        self.type = "CUSTOM"
        self.custom = cmd.split()

    def prepare_cmd(self, *_):
        self.signcmd = copy.deepcopy(self.custom)


# Note: tested with Nitrokey HSM
class SWUSignPKCS11(SWUSign):
    def __init__(self, pin):
        super().__init__()
        self.type = "PKCS11"
        self.custom = ["--pin"]
        self.custom.append(pin)

    def prepare_cmd(self, sw_desc_in, sw_desc_sig):
        self.signcmd = [
            "pkcs11-tool",
            "-s",
            "-m ",
            "SHA256-RSA-PKCS",
            "-i",
            sw_desc_in,
            "-o",
            sw_desc_sig,
        ] + self.custom
