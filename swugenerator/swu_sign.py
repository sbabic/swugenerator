# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
import logging
import subprocess
import sys

from enum import Enum


class SWUSign:
    def __init__(self):
        self.type = None
        self.key = None
        self.cert = None
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
            subprocess.run(self.signcmd, check=True, text=True)
        except subprocess.CalledProcessError:
            logging.critical(
                "SWU cannot be signed, signing command was %s", self.signcmd
            )
            sys.exit(1)


class SWUSignCMS(SWUSign):
    """CMS signature, with one or more signers

    openssl cms takes one password file and one digest for all signers.
    """

    def __init__(self, key, cert, passin, certfile, engine=None, keyform=None,
                 provider=None, provider_path=None):
        super().__init__()
        self.type = "CMS"
        self.key = key
        self.cert = cert
        self.passin = passin
        self.certfile = certfile
        self.engine = engine
        self.keyform = keyform
        self.provider = provider
        self.provider_path = provider_path
        # further signers after (key, cert), and more intermediate certificates
        self.signers = []
        self.certfiles = []
        self.md = None

    def add_signer(self, key, cert, passin=None, certfile=None):
        """Adds a signer: the signature has then one SignerInfo for each"""
        if passin and passin != self.passin:
            if self.passin:
                raise ValueError("CMS signers must use the same password file")
            self.passin = passin
        self.signers.append((key, cert))
        if certfile:
            self.add_certfile(certfile)

    def add_certfile(self, certfile):
        """Adds a file with intermediate certificates"""
        if certfile and certfile != self.certfile and certfile not in self.certfiles:
            self.certfiles.append(certfile)

    def set_md(self, md):
        """Sets the message digest, otherwise the default of the keys"""
        self.md = md

    def get_certfile_args(self):
        certfile_args = super().get_certfile_args()
        for certfile in self.certfiles:
            certfile_args += ["-certfile", certfile]
        return certfile_args

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
        if self.provider_path:
            self.signcmd += ["-provider-path", self.provider_path]
        if self.provider:
            self.signcmd += ["-provider", "default", "-provider", self.provider]
        if self.engine:
            self.signcmd += ["-engine", self.engine]
        if self.keyform:
            self.signcmd += ["-keyform", self.keyform]
        self.signcmd += ["-inkey", self.key]
        for key, cert in self.signers:
            self.signcmd += ["-signer", cert, "-inkey", key]
        if self.md:
            self.signcmd += ["-md", self.md]
        self.signcmd += [
            "-outform",
            "DER",
            "-nosmimecap",
            "-binary",
        ]
        self.signcmd += self.get_passwd_file_args()
        self.signcmd += self.get_certfile_args()


class SWUSignRSA(SWUSign):
    class RSAMode(Enum):
        PKCS1 = "pkcs1"
        PSS = "pss"

    def __init__(self, key, passin, mode=RSAMode.PKCS1):
        super().__init__()
        self.type = "RSA"
        self.key = key
        self.passin = passin
        self.mode = mode

    def _get_rsa_mode_args(self):
        if self.mode == self.RSAMode.PSS:
            return ["-sigopt", "rsa_padding_mode:pss",
                    "-sigopt", "rsa_pss_saltlen:-2"]
        if self.mode == self.RSAMode.PKCS1:
            return []
        raise ValueError(f"Unknown or unsupported RSA mode: {self.mode}")

    def prepare_cmd(self, sw_desc_in, sw_desc_sig):
        self.signcmd = (
            ["openssl", "dgst", "-sha256", "-sign", self.key]
            + self.get_passwd_file_args()
            + self._get_rsa_mode_args()
            + ["-out", sw_desc_sig, sw_desc_in]
        )


class SWUSignCustom(SWUSign):
    def __init__(self, cmd):
        super().__init__()
        self.type = "CUSTOM"
        self.custom = cmd

    def prepare_cmd(self, sw_desc_in, sw_desc_sign):
        self.signcmd = self.custom + [sw_desc_in, sw_desc_sign]


# Note: tested with Nitrokey HSM
class SWUSignPKCS11(SWUSign):
    def __init__(self, pin, module=None, slot=None, obj_id=None):
        super().__init__()
        self.type = "PKCS11"
        self.custom = []
        if module:
            self.custom.extend(["--module", module])
        if slot:
            self.custom.extend(["--slot", slot])
        if obj_id:
            self.custom.extend(["--id", obj_id])
        self.custom.extend(["--pin", pin])

    def prepare_cmd(self, sw_desc_in, sw_desc_sig):
        self.signcmd = [
            "pkcs11-tool",
            "-s",
            "-m",
            "SHA256-RSA-PKCS",
            "-i",
            sw_desc_in,
            "-o",
            sw_desc_sig,
        ] + self.custom
