# SWUGenerator, SWU Package Generator for SWUpdate
#
# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
# pylint: disable=C0114

import argparse
import logging
import os
import sys
import textwrap
from pathlib import Path
from typing import List, Optional, Tuple, Union

import libconf

from swugenerator import __about__, generator
from swugenerator.swu_sign import SWUSignCMS, SWUSignCustom, SWUSignPKCS11, SWUSignRSA


class InvalidKeyFile(ValueError):
    """Raised when a key file is invalid"""


class InvalidSigningOption(ValueError):
    """Raised when an invalid signing option is passed via command line"""


class UpdateAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        cfg = getattr(namespace, self.dest, None)
        if cfg is None:
            cfg = {}
        cfg.update(*values)
        setattr(namespace, self.dest, cfg)


def extract_keys(keyfile: str) -> Tuple[Optional[str], Optional[str]]:
    """Extracts encryption key and initialization vector (IV)

    TODO Ensure alignment of key file with description in docs:
    (https://sbabic.github.io/swupdate/encrypted_images.html#building-an-encrypted-swu-image)

    Args:
        keyfile (str): Path to file containing key and IV

    Raises:
        InvalidKeyFile: If key file cannot be read

    Returns:
        Tuple[Optional[str], Optional[str]]: Key and IV if found.
            Tuple will contain None for either value if missing
    """
    try:
        with open(keyfile, "r", encoding="utf-8") as keyfile_fd:
            lines = keyfile_fd.readlines()
    except IOError as error:
        raise InvalidKeyFile(f"Failed to open key file {keyfile}") from error

    enc_key, init_vec = None, None
    for line in lines:
        key, value = (
            line.replace(" ", "").rstrip("\n").split("=") if len(line.split("=")) == 2 else (None, None)
        )
        if key == "key":
            enc_key = value
        if key == "iv":
            init_vec = value
    return enc_key, init_vec


def parse_config_file(config_file_arg: str) -> dict:
    """Parses configuration file to store key value pairs

    Args:
        config_file_arg (str): Path to config file

    Returns:
        dict: Key value pairs parsed from configuration file
    """
    config_vars = {}
    with open(config_file_arg, "r", encoding="utf-8") as config_fd:
        config = libconf.load(config_fd)
        for key, keydict in config.items():
            if key == "variables":
                for varname, varvalue in keydict.items():
                    logging.debug("VAR = %s VAL = %s", varname, varvalue)
                    config_vars[varname] = varvalue
    return config_vars


def parse_signing_option(
    sign_arg: str,
    engine: str = None,
    keyform: str = None,
) -> Union[SWUSignCMS, SWUSignRSA, SWUSignPKCS11, SWUSignCustom]:
    """Parses signgning option passed by user. Valid options can be found below.

    CMS,<private key>,<certificate used to sign>,<file with password>,<file with certs>
    CMS,<private key>,<certificate used to sign>,<file with password>
    CMS,<private key>,<certificate used to sign>
    RSA,<private key>,<file with password>
    RSA,<private key>
    PKCS11,<pin>[,<module>]
    CUSTOM,<custom command>

    Args:
        sign_arg (str): argument passed by user
        engine (str): OpenSSL engine to use for signing (e.g., pkcs11)
        keyform (str): Key format to use for signing (e.g., engine)

    Raises:
        InvalidSigningOption: If option passed by user is invalid

    Returns:
        Union[SWUSignCMS, SWUSignRSA, SWUSignPKCS11, SWUSignCustom]: Signing option to use
    """
    sign_parms = sign_arg.split(",")
    cmd = sign_parms[0]
    if cmd == "CMS":
        if len(sign_parms) not in (3, 4, 5) or not all(sign_parms[0:2]):
            raise InvalidSigningOption(
                "CMS requires private key, certificate, an optional password file and an optional file with additional certificates"
            )
        # Format : CMS,<private key>,<certificate used to sign>,<file with password>,<file with certs>
        if len(sign_parms) == 5:
            return SWUSignCMS(sign_parms[1], sign_parms[2], sign_parms[3], sign_parms[4], engine, keyform)
        # Format : CMS,<private key>,<certificate used to sign>,<file with password>
        elif len(sign_parms) == 4:
            return SWUSignCMS(sign_parms[1], sign_parms[2], sign_parms[3], None, engine, keyform)
        # Format : CMS,<private key>,<certificate used to sign>
        else:
            return SWUSignCMS(sign_parms[1], sign_parms[2], None, None, engine, keyform)
    if cmd == "RSA":
        if len(sign_parms) not in (2, 3) or not all(sign_parms):
            raise InvalidSigningOption(
                "RSA requires private key and an optional password file"
            )
        # Format : RSA,<private key>,<file with password>
        if len(sign_parms) == 3:
            return SWUSignRSA(sign_parms[1], sign_parms[2])
        # Format : RSA,<private key>
        return SWUSignRSA(sign_parms[1], None)
    if cmd == "PKCS11":
        # Format : PKCS11,<pin>[,<module>]
        if len(sign_parms) not in (2, 3) or not all(sign_parms[0:2]):
            raise InvalidSigningOption("PKCS11 requires pin and optional module path")
        pin = sign_parms[1]
        module = sign_parms[2] if len(sign_parms) == 3 else None
        return SWUSignPKCS11(pin, module)
    if cmd == "CUSTOM":
        # Format : CUSTOM,<custom command>
        if len(sign_parms) < 2 or not all(sign_parms):
            raise InvalidSigningOption("CUSTOM requires custom command")
        return SWUSignCustom(sign_parms[1:])
    raise InvalidSigningOption("Unknown signing command")


def set_log_level(arg: str) -> str:
    """Sets log level

    This is meant to be used with Argparse's type param for
    add_argument, but this allows log level to be set when
    argparse parses commands.

    Args:
        arg (str): Log level in string form (All caps)

    Returns:
        str: Returns arg to be parsed by argparse.
            Argparse will then make sure arg is in choices
            and return an error to the user otherwise.
    """
    if arg in ("DEBUG", "INFO", "ERROR", "CRITICAL"):
        logging.basicConfig(level=logging.getLevelName(arg))
    return arg


def create_swu(args: argparse.Namespace) -> None:
    """Creates SWU archive from arguments passed to SWUGenerate

    Args:
        args (argparse.Namespace): Parsed arguments to generate SWU file with
    """
    # Extract key and iv from encryption_key_file (Will default to '(None, None)')
    key, init_vec = args.encryption_key_file

    # Add current working directory to search path
    args.artifactory.append(Path(os.getcwd()))

    # Pass engine and keyform to parse_signing_option if sign is set
    if hasattr(args, 'sign') and args.sign and isinstance(args.sign, str):
        args.sign = parse_signing_option(args.sign, args.engine, args.keyform)

    swu = generator.SWUGenerator(
        args.sw_description,
        args.swu_file,
        args.config,
        args.artifactory,
        args.sign,
        key,
        init_vec,
        args.encrypt_swdesc,
        args.no_compress,
        args.no_encrypt,
        args.no_ivt,
        args.no_hash,
    )
    swu.process()
    swu.close()


def parse_args(args: List[str]) -> None:
    """Sets up arguments for swugenerator and parses commandline args

    Args:
        args (List[str]): Command line arguments
    """
    parser = argparse.ArgumentParser(
        prog=__about__.__title__,
        description=__about__.__summary__ + " " + __about__.__version__,
        fromfile_prefix_chars="@",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-K",
        "--encryption-key-file",
        default=(None, None),
        type=extract_keys,
        help="<key,iv> : AES Key to encrypt artifacts",
    )

    parser.add_argument(
        "-n",
        "--no-compress",
        action="store_true",
        help="Do not compress files",
    )

    parser.add_argument(
        "-e",
        "--no-encrypt",
        action="store_true",
        help="Do not encrypt files",
    )

    parser.add_argument(
        "-x",
        "--no-ivt",
        action="store_true",
        help="Do not generate IV when encrypting",
    )

    parser.add_argument(
        "-y",
        "--no-hash",
        action="store_true",
        help="Do not store sha256 hash in sw-description",
    )

    parser.add_argument(
        "-k",
        "--sign",
        help=textwrap.dedent(
            """\
            RSA key or certificate to sign the SWU
            One of :
            CMS,<private key>,<certificate used to sign>,<file with password if any>,<file with certs if any>
                 -g, --engine ENGINE       OpenSSL engine to use for signing (e.g., pkcs11)
                 -f, --keyform KEYFORM     Key format to use for signing (e.g., engine)
            RSA,<private key>,<file with password if any>
            PKCS11,<pin>[,<module>]
            CUSTOM,<custom command> """
        ),
    )

    parser.add_argument(
        "-s",
        "--sw-description",
        required=True,
        type=lambda p: Path(p).resolve(),
        help="sw-description template",
    )

    parser.add_argument(
        "-t",
        "--encrypt-swdesc",
        action="store_const",
        const=True,
        default=False,
        help="Encrypt sw-description",
    )

    parser.add_argument(
        "-a",
        "--artifactory",
        default=[],
        type=lambda paths: [Path(p).resolve() for p in paths.split(",")],
        help="list of directories where artifacts are searched",
    )

    parser.add_argument(
        "-o",
        "--swu-file",
        required=True,
        type=Path,
        help="SWU output file",
    )

    parser.register("action", "update", UpdateAction)
    parser.add_argument(
        "-c",
        "--config",
        default={},
        action="update",
        nargs="*",
        type=parse_config_file,
        help="configuration file",
    )

    parser.add_argument(
        "-l",
        "--loglevel",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="WARNING",
        type=set_log_level,
        help="set log level, default is WARNING",
    )

    parser.add_argument(
        "-g",
        "--engine",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-f",
        "--keyform",
        default=None,
        help=argparse.SUPPRESS,
    )

    subparsers = parser.add_subparsers(
        title="command", help="command to be executed", required=True
    )
    create_subparser = subparsers.add_parser("create", help="creates a SWU file")
    create_subparser.set_defaults(func=create_swu)

    args = parser.parse_args(args)
    if hasattr(args, 'sign') and args.sign:
        args.sign = parse_signing_option(args.sign, args.engine, args.keyform)
    args.func(args)


def main():
    """Main entry point for SWUGenerator"""
    # Arg parsing is in separate function
    # to allow argument parsing to be easily
    # tested with pytest
    parse_args(sys.argv[1:])


if __name__ == "__main__":
    main()
