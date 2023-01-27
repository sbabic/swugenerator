# pylint: disable=C0114,C0116,W0621
import argparse
import libconf
import pytest

from swugenerator import main
from swugenerator.swu_sign import SWUSignCMS, SWUSignCustom, SWUSignPKCS11, SWUSignRSA

VALID_KEY = "390ad54490a4a5f53722291023c19e08ffb5c4677a59e958c96ffa6e641df040"
VALID_IV = "d5d601bacfe13100b149177318ebc7a4"
VALID_KEY_FILE = "valid_key.txt"
INVALID_KEY_FILE = "invalid_key.txt"


@pytest.fixture(scope="session")
def test_dir(tmp_path_factory):
    """Creates a directory to test"""
    test_space = tmp_path_factory.mktemp("archive")
    return test_space


#### Key file parsing tests ####
@pytest.fixture(scope="session")
def valid_key_file(test_dir):
    key_file = test_dir / VALID_KEY_FILE
    with key_file.open("w") as key_file_fd:
        key_file_fd.write(f"key={VALID_KEY}\niv={VALID_IV}")
    return key_file


@pytest.fixture(scope="session")
def invalid_key_file(test_dir):
    # Create invalid key file where only the key can be parsed
    key_file = test_dir / INVALID_KEY_FILE
    with key_file.open("w") as key_file_fd:
        key_file_fd.write(f"key foo\nkey={VALID_KEY}\nkey bar\niv\n{VALID_IV}")
    return key_file


def test_extract_keys_returns_valid_tuple_from_valid_file(valid_key_file):
    assert main.extract_keys(str(valid_key_file)) == (VALID_KEY, VALID_IV)


def test_extract_keys_returns_none_from_key_file_thats_invalid(invalid_key_file):
    assert main.extract_keys(str(invalid_key_file)) == (VALID_KEY, None)


def test_extract_keys_returns_exception_from_key_file_that_dne():
    with pytest.raises(main.InvalidKeyFile):
        main.extract_keys("foo/bar/baz.txt")


#### Config file parsing tests ####
VALID_CONFIG = {"foo": 1, "bar": "test"}
VALID_CONFIG_FILE = "valid.cfg"
INVALID_CONFIG_FILE = "invalid.cfg"


@pytest.fixture(scope="session")
def valid_config_file(test_dir):
    config_file = test_dir / VALID_CONFIG_FILE
    with config_file.open("w") as config_file_fd:
        config_file_fd.write(libconf.dumps({"variables": VALID_CONFIG}))
    return config_file


@pytest.fixture(scope="session")
def invalid_config_file(test_dir):
    config_file = test_dir / VALID_CONFIG_FILE
    with config_file.open("w") as config_file_fd:
        config_file_fd.write("{" + libconf.dumps({"variables": VALID_CONFIG}))
    return config_file


def test_valid_config_file_is_properly_parsed(valid_config_file):
    assert main.parse_config_file(str(valid_config_file)) == VALID_CONFIG


def test_invalid_config_file_throws_exception(invalid_config_file):
    with pytest.raises(libconf.ConfigParseError):
        main.parse_config_file(str(invalid_config_file))


def test_missing_config_file_throws_exception():
    with pytest.raises(FileNotFoundError):
        main.parse_config_file("foo/bar/baz.txt")


#### Signing option parsing tests ####
SIGNING_TEST_PARAMETERS = [
    ("CMS,foo,bar,baz", SWUSignCMS("foo", "bar", "baz")),
    ("CMS,foo,bar", SWUSignCMS("foo", "bar", None)),
    ("RSA,foo,bar", SWUSignRSA("foo", "bar")),
    ("RSA,foo", SWUSignRSA("foo", None)),
    ("PKCS11,foo", SWUSignPKCS11("foo")),
    ("CUSTOM,foo", SWUSignCustom("foo")),
]


@pytest.mark.parametrize("arg,expected", SIGNING_TEST_PARAMETERS)
def test_valid_siging_params_parsed_to_correct_signing_obj(arg, expected):
    signing_option = main.parse_signing_option(arg)
    assert type(signing_option) == type(expected)
    assert signing_option.type == expected.type
    assert signing_option.key == expected.key
    assert signing_option.cert == expected.cert
    assert signing_option.passin == expected.passin


INVALID_SIGNING_TEST_PARAMETERS = [
    ("CMS", "CMS requires private key, certificate, and an optional password file"),
    ("CMS,", "CMS requires private key, certificate, and an optional password file"),
    ("CMS,,", "CMS requires private key, certificate, and an optional password file"),
    ("CMS,,,", "CMS requires private key, certificate, and an optional password file"),
    ("CMS,,,,", "CMS requires private key, certificate, and an optional password file"),
    (
        "CMS,,foo,",
        "CMS requires private key, certificate, and an optional password file",
    ),
    ("CMS,foo", "CMS requires private key, certificate, and an optional password file"),
    (
        "CMS,foo,bar,baz,jaz",
        "CMS requires private key, certificate, and an optional password file",
    ),
    ("RSA,foo,bar,baz", "RSA requires private key and an optional password file"),
    ("PKCS11", "PKCS11 requires URI"),
    ("PKCS11,", "PKCS11 requires URI"),
    ("PKCS11,,", "PKCS11 requires URI"),
    ("PKCS11,foo,", "PKCS11 requires URI"),
    ("CUSTOM", "CUSTOM requires custom command"),
    ("CUSTOM,", "CUSTOM requires custom command"),
    ("CUSTOM,,", "CUSTOM requires custom command"),
    ("CUSTOM,foo,", "CUSTOM requires custom command"),
    ("FOO", "Unknown signing command"),
    ("FOO,bar,baz", "Unknown signing command"),
]


@pytest.mark.parametrize("arg,exception_msg", INVALID_SIGNING_TEST_PARAMETERS)
def test_invalid_signing_params_throws_exception_with_correct_msg(arg, exception_msg):
    with pytest.raises(main.InvalidSigningOption) as error:
        main.parse_signing_option(arg)
    assert exception_msg in error.value.args


#### Parse args tests ####
@pytest.fixture
def mock_main_funcs(monkeypatch):
    def mock_create_swu(*_):
        return True

    def mock_extract_keys(*_):
        return "foo", "bar"

    def mock_parse_signing_option(*_):
        return SWUSignCMS("foo", "bar", "baz")

    def mock_parse_config_file(*_):
        return {}

    def mock_argparse_error(*_):
        raise Exception

    monkeypatch.setattr(main, "create_swu", mock_create_swu)
    monkeypatch.setattr(main, "extract_keys", mock_extract_keys)
    monkeypatch.setattr(main, "parse_signing_option", mock_parse_signing_option)
    monkeypatch.setattr(main, "parse_config_file", mock_parse_config_file)
    monkeypatch.setattr(argparse.ArgumentParser, "exit", mock_argparse_error)


VALID_COMMANDS = [
    (["-s", "sw-description", "-o", "test.swu", "create"]),
    (["--sw-description", "sw-description", "--swu-file", "test.swu", "create"]),
    (
        [
            "-K",
            "key.txt",
            "-n",
            "-e",
            "-x",
            "-k",
            "CUSTOM,foo",
            "-s",
            "sw-description",
            "-t",
            "-a",
            ".,..",
            "-o",
            "test.swu",
            "-c",
            "test.cfg",
            "-l",
            "DEBUG",
            "create",
        ]
    ),
    (
        [
            "--encryption-key-file",
            "key.txt",
            "--no-compress",
            "--no-encrypt",
            "--no-ivt",
            "--sign",
            "CUSTOM,foo",
            "--sw-description",
            "sw-description",
            "--encrypt-swdesc",
            "--artifactory",
            ".,..",
            "--swu-file",
            "test.swu",
            "--config",
            "test.cfg",
            "--loglevel",
            "DEBUG",
            "create",
        ]
    ),
]


@pytest.mark.parametrize("args", VALID_COMMANDS)
def test_parsing_valid_args_doesnt_throw(args, mock_main_funcs):
    main.parse_args(args)


INVALID_COMMANDS = [
    (["-s", "sw-description", "-o", "test.swu"]),
    (["-s", "-o", "test.swu", "create"]),
    (["-s", "sw-description", "-o", "create"]),
    (["-s", "-o", "create"]),
    (["-s", "-o"]),
    (["-K", "-s", "sw-description", "-o", "test.swu", "create"]),
    (["-k", "-s", "sw-description", "-o", "test.swu", "create"]),
    (["-a", "sw-description", "-o", "test.swu", "create"]),
    (["-c", "sw-description", "-o", "test.swu", "create"]),
    (["-l", "sw-description", "-o", "test.swu", "create"]),
    (["-l", "baz", "sw-description", "-o", "test.swu", "create"]),
]


@pytest.mark.parametrize("args", INVALID_COMMANDS)
def test_parsing_invalid_args_does_throw_argparse_exception(args, mock_main_funcs):
    with pytest.raises(Exception):
        main.parse_args(args)
