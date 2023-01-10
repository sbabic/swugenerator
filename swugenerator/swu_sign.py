# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
import subprocess
import logging


class SWUSign:
    def __init__(self):
        self.type = None
        self.key = None
        self.cert = None
        self.cmd = None
        self.passin = None
        self.signcmd = []

    def get_passwd_file_args(self):
        passwd_args = []
        if self.passin:
            passwd_args = ["-passin", "file:%s" % self.passin]
        return passwd_args

    def set_password_file(self, passin):
        self.passin = passin

    def sign(self):
        result = None
        try:
            subprocess.run(' '.join(self.signcmd), shell=True, check=True,  text=True)
        except:
            logging.critical('SWU cannot be signed, signing command was %s' % self.signcmd)
            exit(1)


class SWUSignCMS(SWUSign):
    def __init__(self, key, cert, passin):
        super(SWUSignCMS, self).__init__()
        self.type = "CMS"
        self.key = key
        self.cert = cert
        self.passin = passin

    def prepare_cmd(self, sw_desc_in, sw_desc_sig):
        self.signcmd = ["openssl", "cms", "-sign", "-in", sw_desc_in, "-out", sw_desc_sig, "-signer", self.cert]
        self.signcmd += ["-inkey", self.key, "-outform", "DER", "-nosmimecap", "-binary"]
        self.signcmd += self.get_passwd_file_args()


class SWUSignRSA(SWUSign):
    def __init__(self, key, passin):
        super(SWUSignRSA, self).__init__()
        self.type = "RSA"
        self.key = key
        self.passin = passin

    def prepare_cmd(self, sw_desc_in, sw_desc_sig):
        self.signcmd = ["openssl", "dgst", "-sha256", "-sign", self.key] + \
                       self.get_passwd_file_args() +\
                       ["-out", sw_desc_sig, sw_desc_in]


class SWUSignCustom(SWUSign):
    def __init__(self, cmd):
        super(SWUSignCustom, self).__init__()
        self.type = "CUSTOM"
        self.custom = cmd.split()

    def prepare_cmd(self, sw_desc_in, sw_desc_sig=None):
        self.signcmd = []
        for i in range(len(self.custom)):
            self.signcmd.append(self.custom[i])


# Note: tested with Nitrokey HSM
class SWUSignPKCS11(SWUSign):
    def __init__(self, pin):
        super(SWUSignPKCS11, self).__init__()
        self.type = "PKCS11"
        self.custom = ['--pin']
        self.custom.append(pin)

    def prepare_cmd(self, sw_desc_in, sw_desc_sig):
        self.signcmd = ['pkcs11-tool', '-s', '-m ', 'SHA256-RSA-PKCS', '-i', sw_desc_in, '-o', sw_desc_sig] + self.custom

