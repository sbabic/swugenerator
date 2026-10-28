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

from swugenerator import __about__, generator, mender, signer, swu_file

from swugenerator.swu_sign import SWUSignCMS, SWUSignCustom, SWUSignPKCS11, SWUSignRSA


class InvalidKeyFile(ValueError):
    """Raised when a key file is invalid"""


class InvalidSigningOption(ValueError):
    """Raised when an invalid signing option is passed via command line"""


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
    provider: str = None,
    provider_path: str = None,
) -> Union[SWUSignCMS, SWUSignRSA, SWUSignPKCS11, SWUSignCustom]:
    """Parses signgning option passed by user. Valid options can be found below.

    CMS,<private key>,<certificate used to sign>,<file with password>,<file with certs>
    CMS,<private key>,<certificate used to sign>,<file with password>
    CMS,<private key>,<certificate used to sign>
    RSA,<private key>,<file with password>
    RSA,<private key>
    RSAPSS,<private key>,<file with password>
    RSAPSS,<private key>
    PKCS11,<pin>[,<module>,<slot>,<id>]
    CUSTOM,<custom command>

    Args:
        sign_arg (str): argument passed by user
        engine (str): OpenSSL engine to use for signing (e.g., pkcs11)
        keyform (str): Key format to use for signing (e.g., engine)
        provider (str): OpenSSL provider to load (e.g., pkcs11)
        provider_path (str): Path to OpenSSL provider modules

    Raises:
        InvalidSigningOption: If option passed by user is invalid

    Returns:
        Union[SWUSignCMS, SWUSignRSA, SWUSignPKCS11, SWUSignCustom]: Signing option to use
    """
    sign_parms = sign_arg.split(",")
    cmd = sign_parms[0]
    if cmd == "CMS":
        if len(sign_parms) not in (3, 4, 5) or not all(sign_parms[1:3]):
            raise InvalidSigningOption(
                "CMS requires private key, certificate, an optional password file and an optional file with additional certificates"
            )
        # Format : CMS,<private key>,<certificate used to sign>,<file with password>,<file with certs>
        if len(sign_parms) == 5:
            return SWUSignCMS(sign_parms[1], sign_parms[2], sign_parms[3], sign_parms[4], engine, keyform, provider, provider_path)
        # Format : CMS,<private key>,<certificate used to sign>,<file with password>
        if len(sign_parms) == 4:
            return SWUSignCMS(sign_parms[1], sign_parms[2], sign_parms[3], None, engine, keyform, provider, provider_path)
        # Format : CMS,<private key>,<certificate used to sign>
        return SWUSignCMS(sign_parms[1], sign_parms[2], None, None, engine, keyform, provider, provider_path)
    if cmd[:3] == "RSA":
        if len(sign_parms) not in (2, 3) or not all(sign_parms):
            raise InvalidSigningOption(
                "RSA requires private key and an optional password file"
            )
        if cmd == "RSA":
            mode = SWUSignRSA.RSAMode.PKCS1
        elif cmd == "RSAPSS":
            mode = SWUSignRSA.RSAMode.PSS
        else:
            raise InvalidSigningOption(f"Unknown RSA mode: {cmd}")
        # Format : RSA(PSS),<private key>,<file with password>
        if len(sign_parms) == 3:
            return SWUSignRSA(sign_parms[1], sign_parms[2], mode=mode)
        # Format : RSA(PSS),<private key>
        return SWUSignRSA(sign_parms[1], None, mode=mode)
    if cmd == "PKCS11":
        # Format : PKCS11,<pin>[,<module>,<slot>,<id>]
        if len(sign_parms) not in range(2, 6) or not all(sign_parms[0:2]):
            raise InvalidSigningOption("PKCS11 requires pin and optional parameters such as module path, slot or id")
        pin = sign_parms[1]
        module = sign_parms[2] if len(sign_parms) > 2 else None
        slot   = sign_parms[3] if len(sign_parms) > 3 else None
        obj_id = sign_parms[4] if len(sign_parms) > 4 else None

        return SWUSignPKCS11(pin, module, slot, obj_id)
    if cmd == "CUSTOM":
        # Format : CUSTOM,<custom command>
        if len(sign_parms) < 2 or not all(sign_parms):
            raise InvalidSigningOption("CUSTOM requires custom command")
        return SWUSignCustom(sign_parms[1:])
    raise InvalidSigningOption("Unknown signing command")


# pylint: disable=too-many-arguments,too-many-positional-arguments
def parse_signing_options(
    sign_args: List[str],
    engine: str = None,
    keyform: str = None,
    provider: str = None,
    provider_path: str = None,
    cms_md: str = None,
    cms_certfiles: List[str] = None,
) -> Union[SWUSignCMS, SWUSignRSA, SWUSignPKCS11, SWUSignCustom]:
    """Parses the -k options: several are allowed for CMS only

    With several CMS options, the signature has a signer for each.

    Raises:
        InvalidSigningOption: if the options cannot be combined
    """
    signers = [
        parse_signing_option(arg, engine, keyform, provider, provider_path)
        for arg in sign_args
    ]
    sign = signers[0]
    if len(signers) > 1:
        if not all(isinstance(s, SWUSignCMS) for s in signers):
            raise InvalidSigningOption("Only CMS can be given more than once")
        for other in signers[1:]:
            try:
                sign.add_signer(other.key, other.cert, other.passin, other.certfile)
            except ValueError as error:
                raise InvalidSigningOption(str(error)) from error
    if cms_md or cms_certfiles:
        if not isinstance(sign, SWUSignCMS):
            raise InvalidSigningOption("--cms-md and --cms-certfile need CMS signing")
        if cms_md:
            sign.set_md(cms_md)
        for certfile in cms_certfiles or []:
            sign.add_certfile(certfile)
    return sign


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


def payload_type(arg: str) -> str:
    """Checks the payload type of a Mender Artifact

    Raises:
        argparse.ArgumentTypeError: if it is empty or has spaces
    """
    if not arg or any(c.isspace() for c in arg):
        raise argparse.ArgumentTypeError("must be a name without spaces")
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
        args.add_file,
        args.keep_names,
    )
    try:
        swu.process()
        swu.close()
    except BaseException:
        swu.abort()
        raise

def sign_swu(args: argparse.Namespace) -> None:
    swu = signer.SWUSigner(
        args.swu_in_file,
        args.swu_file,
        args.sign
    )
    try:
        swu.process()
        swu.close()
    except BaseException:
        swu.abort()
        raise

def mender_swu(args: argparse.Namespace) -> None:
    """Wraps an existing SWU into a Mender Artifact

    Args:
        args (argparse.Namespace): Parsed arguments
    """
    swu = mender.SWUMender(
        args.swu_in_file,
        args.swu_file,
        args.device_type,
        args.artifact_name,
        args.payload_type,
        args.compression,
    )
    try:
        swu.process()
        swu.close()
    except BaseException:
        swu.abort()
        raise

def extract_swu(args: argparse.Namespace) -> None:
    """Extracts the files of a SWU as they are, also the ones of 4 GiB and more

    Args:
        args (argparse.Namespace): Parsed arguments
    """
    try:
        with open(args.swu_in_file, "rb") as swu:
            names = swu_file.SWUFile(swu).extract(str(args.directory))
    except (swu_file.FormatException, swu_file.MagicException, OSError) as error:
        logging.critical("Cannot extract %s: %s", args.swu_in_file, error)
        sys.exit(1)
    for name in names:
        logging.info("extracted %s", name)

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
        help=textwrap.dedent(
            """\
            Do not encrypt files, for artifacts that are already encrypted.
            encrypted and ivt are kept as set in sw-description"""
        ),
    )

    parser.add_argument(
        "-x",
        "--no-ivt",
        action="store_true",
        help="Do not generate IV when encrypting",
    )

    parser.add_argument(
        "--keep-names",
        action="store_true",
        help=textwrap.dedent(
            """\
            Store encrypted artifacts under their name, without the suffix .enc
            in the SWU and in sw-description"""
        ),
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
        action="append",
        help=textwrap.dedent(
            """\
            RSA key or certificate to sign the SWU
            One of :
            CMS,<private key>,<certificate used to sign>,<file with password if any>,<file with certs if any>
                 -g, --engine ENGINE       OpenSSL engine to use for signing (e.g., pkcs11)
                 -f, --keyform KEYFORM     Key format to use for signing (e.g., engine)
                 -p, --provider PROVIDER   OpenSSL provider to load (e.g., pkcs11)
                 --provider-path PATH      Path to OpenSSL provider modules
            RSA,<private key>,<file with password if any>
            PKCS11,<pin>[,<module>,<slot>,<id>]
            CUSTOM,<custom command>
            CMS can be given more than once, for a signature with several
            signers; they must use the same password file."""
        ),
    )

    parser.add_argument(
        "--cms-md",
        default=None,
        help="message digest for CMS signing (openssl cms -md), "
        "default: the one of the keys",
    )

    parser.add_argument(
        "--cms-certfile",
        action="append",
        default=[],
        help="file with intermediate certificates for CMS signing, can be repeated",
    )

    parser.add_argument(
        "--add-file",
        action="append",
        default=[],
        help="file searched in the artifactory and added to the SWU as it is, "
        "even if sw-description does not use it, can be repeated",
    )

    parser.add_argument(
        "-s",
        "--sw-description",
        required=False,
        type=lambda p: Path(p).resolve(),
        help="sw-description template, required for the create command",
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
        type=Path,
        help="SWU output file, required for create, sign and mender",
    )

    parser.add_argument(
        "-c",
        "--config",
        default={},
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
    parser.add_argument(
        "-p",
        "--provider",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--provider-path",
        default=None,
        help=argparse.SUPPRESS,
    )

    subparsers = parser.add_subparsers(
        title="command", help="command to be executed", required=True
    )
    create_subparser = subparsers.add_parser("create", help="creates a SWU file")
    create_subparser.set_defaults(func=create_swu)
    sign_subparser = subparsers.add_parser("sign", help="signs an existing SWU file provided by -i")
    sign_subparser.set_defaults(func=sign_swu)
    sign_subparser.add_argument(
        "-i",
        "--swu-in-file",
        required=True,
        type=Path,
        help="SWU input file to be signed, required for the sign command",
    )
    extract_subparser = subparsers.add_parser(
        "extract", help="extracts the files of an existing SWU file provided by -i"
    )
    extract_subparser.set_defaults(func=extract_swu)
    extract_subparser.add_argument(
        "-i",
        "--swu-in-file",
        required=True,
        type=Path,
        help="SWU to extract",
    )
    extract_subparser.add_argument(
        "-d",
        "--directory",
        default=Path("."),
        type=Path,
        help="output directory, default: the current directory",
    )
    mender_subparser = subparsers.add_parser(
        "mender",
        help="wraps an existing SWU file provided by -i into a Mender Artifact",
    )
    mender_subparser.set_defaults(func=mender_swu)
    mender_subparser.add_argument(
        "-i",
        "--swu-in-file",
        required=True,
        type=Path,
        help="SWU to wrap",
    )
    mender_subparser.add_argument(
        "-D",
        "--device-type",
        action="append",
        required=True,
        help="compatible device type, can be repeated",
    )
    mender_subparser.add_argument(
        "-N",
        "--artifact-name",
        default=None,
        help="artifact name, default: version in sw-description",
    )
    mender_subparser.add_argument(
        "-T",
        "--payload-type",
        default="swu",
        type=payload_type,
        help="payload type, default: swu",
    )
    mender_subparser.add_argument(
        "-C",
        "--compression",
        choices=list(mender.COMPRESSION),
        default="gzip",
        help="compression of header and payload, default: gzip",
    )
    args = parser.parse_args(args)
    if args.sign:
        try:
            args.sign = parse_signing_options(args.sign, args.engine, args.keyform,
                                              args.provider, args.provider_path,
                                              args.cms_md, args.cms_certfile)
        except InvalidSigningOption as error:
            parser.error(str(error))
    elif args.cms_md or args.cms_certfile:
        parser.error("--cms-md and --cms-certfile need -k/--sign with CMS")
    if args.func is extract_swu:
        # the files are extracted as they are, nothing is written into a SWU
        if args.swu_file or args.sign or args.encryption_key_file != (None, None) \
                or args.encrypt_swdesc:
            parser.error(
                "-o/--swu-file, -k/--sign, -K/--encryption-key-file and "
                "-t/--encrypt-swdesc cannot be used with extract"
            )
    elif not args.swu_file:
        parser.error("the following arguments are required: -o/--swu-file")
    if args.func is create_swu and not args.sw_description:
        parser.error(
            "the following arguments are required: -s/--sw-description"
        )
    # the SWU is wrapped as it is: nothing is signed or encrypted
    if args.func is mender_swu and (
        args.sign or args.encryption_key_file != (None, None) or args.encrypt_swdesc
    ):
        parser.error(
            "-k/--sign, -K/--encryption-key-file and -t/--encrypt-swdesc cannot be "
            "used with mender: sign the SWU before it is wrapped"
        )
    if args.func is sign_swu and not args.sign:
        parser.error(
            "the following arguments are required: -k/--sign"
        )

    args.func(args)


def main():
    """Main entry point for SWUGenerator"""
    # Arg parsing is in separate function
    # to allow argument parsing to be easily
    # tested with pytest
    parse_args(sys.argv[1:])


if __name__ == "__main__":
    main()
