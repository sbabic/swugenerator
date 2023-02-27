# pylint: disable=C0114,C0116,W0621
"""This file hosts integration tests to ensure tool creates valid SWUs"""
from pathlib import Path
import pytest
import shutil

import libarchive

from swugenerator import main

VALID_KEY = "390ad54490a4a5f53722291023c19e08ffb5c4677a59e958c96ffa6e641df040"
VALID_IV = "d5d601bacfe13100b149177318ebc7a4"
UPDATE_FILES = [
    "rootfs.ubifs",
    "swupdate.ext3.gz.u-boot",
    "sdcard.ext3.gz",
    "bootlogo.bmp",
    "uImage.bin",
    "fpga.txt",
    "bootloader-env",
    "README",
    "erase_at_end",
    "display_info",
]


@pytest.fixture()
def input_directory(tmp_path_factory):
    """Creates a directory to test"""
    return tmp_path_factory.mktemp("input_files")


@pytest.fixture()
def output_directory(tmp_path_factory):
    """Creates a directory to test"""
    return tmp_path_factory.mktemp("output_files")


@pytest.fixture()
def artifactory(input_directory):
    """Creates test files that match the filenames in the sw-description"""
    for filename in UPDATE_FILES:
        file = input_directory / filename
        with file.open("w") as file_fd:
            file_fd.write("THIS IS A TEST UPDATE FILE\n")
    return input_directory.resolve()


def copy_to_test_dir(filename, test_dir) -> Path:
    """Helper function to copy integration test inputs to test directory"""
    source_path = Path(__file__).parent / "test_data/integration_input" / filename
    dest_path = test_dir / filename
    shutil.copy(source_path, dest_path)
    return dest_path.resolve()


@pytest.fixture()
def sw_description_template(input_directory):
    """Copies sw-description template to test directory"""
    filename = "sw-description.in"
    return copy_to_test_dir(filename, input_directory)


@pytest.fixture()
def encrypted_sw_description_template(input_directory):
    """Copies sw-description template to test directory"""
    filename = "enc-sw-description.in"
    return copy_to_test_dir(filename, input_directory)


@pytest.fixture()
def config_file(input_directory):
    """Copies config file to test directory"""
    filename = "config"
    return copy_to_test_dir(filename, input_directory)


@pytest.fixture()
def signing_key(input_directory):
    """Creates signing key"""
    filename = "private.pem"
    return copy_to_test_dir(filename, input_directory)


@pytest.fixture()
def encryption_key(input_directory):
    """Creates encryption key"""
    encryption_key_filename = "valid_key.txt"
    encryption_key_path = input_directory / encryption_key_filename
    with encryption_key_path.open("w") as key_key_fd:
        key_key_fd.write(f"key={VALID_KEY}\niv={VALID_IV}")
    return encryption_key_path


def validate_swu(output_swu, encrypted=False):
    """Helper function to validate the output file against a pre-generated output file"""
    reference_swu = (
        Path(__file__).parent / "test_data/integration_output" / output_swu.name
    )
    with libarchive.Archive(output_swu.open()) as output, libarchive.Archive(
        reference_swu.open()
    ) as reference:
        for output_file, reference_file in zip(output, reference):
            if output_file.pathname != reference_file.pathname:
                print("Names do not match")
                return False
            if output_file.size != reference_file.size:
                print("Sizes do not match")
                return False
            if not encrypted and output.read(output_file.size) != reference.read(
                output_file.size
            ):
                print("File contents are not equal")
                return False
    return True


def test_basic_command_creates_valid_swu(
    artifactory, sw_description_template, config_file, output_directory
):
    output_file = "output.swu"
    command_args = [
        "-s",
        str(sw_description_template),
        "-a",
        str(artifactory),
        "-c",
        str(config_file),
        "-o",
        str((output_directory / output_file).resolve()),
        "create",
    ]
    main.parse_args(command_args)
    assert validate_swu(output_directory / output_file)


def test_command_with_sign_flag_creates_valid_signed_swu(
    artifactory, sw_description_template, config_file, signing_key, output_directory
):
    output_file = "signed_output.swu"
    command_args = [
        "-s",
        str(sw_description_template),
        "-a",
        str(artifactory),
        "-c",
        str(config_file),
        "-k",
        f"RSA,{signing_key}",
        "-o",
        str((output_directory / output_file).resolve()),
        "create",
    ]
    main.parse_args(command_args)
    assert validate_swu(output_directory / output_file)


def test_command_with_encryption_flag_creates_encrypted_swu(
    artifactory,
    encrypted_sw_description_template,
    config_file,
    encryption_key,
    output_directory,
):
    output_file = "output.swu.enc"
    command_args = [
        "-s",
        str(encrypted_sw_description_template),
        "-a",
        str(artifactory),
        "-c",
        str(config_file),
        "-K",
        str(encryption_key),
        "-o",
        str((output_directory / output_file).resolve()),
        "create",
    ]
    main.parse_args(command_args)
    assert validate_swu(output_directory / output_file, encrypted=True)


def test_command_with_sign_flag_and_encrypt_flag_creates_signed_encrypted_swu(
    artifactory,
    encrypted_sw_description_template,
    config_file,
    signing_key,
    encryption_key,
    output_directory,
):
    output_file = "signed_output.swu.enc"
    command_args = [
        "-s",
        str(encrypted_sw_description_template),
        "-a",
        str(artifactory),
        "-c",
        str(config_file),
        "-k",
        f"RSA,{signing_key}",
        "-K",
        str(encryption_key),
        "-o",
        str((output_directory / output_file).resolve()),
        "create",
    ]
    main.parse_args(command_args)
    assert validate_swu(output_directory / output_file, encrypted=True)
