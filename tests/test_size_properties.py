# pylint: disable=C0114,C0116,W0621
"""Tests of decompressed-size and decrypted-size, and of no-decompressed-size"""
import shutil
import subprocess

import libconf
import pytest

from swugenerator import main
from swugenerator.swu_file import SWUFile

KEY = "aa" * 32
IV = "bb" * 16
DATA = b"swupdate artifact\n" * 5000

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None or shutil.which("zstd") is None,
    reason="needs openssl and zstd",
)

COMPRESSED = 'compressed = "zstd";'
ENCRYPTED = "encrypted = true;"
BOTH = COMPRESSED + " " + ENCRYPTED
NO_SIZE = "no-decompressed-size = true;"


def entry(attributes):
    return '{ filename = "image.bin"; type = "raw"; device = "/dev/null"; %s }' % attributes


def create(tmp_path, images, files=()):
    """Builds a SWU, returns its images and files with their stored size"""
    (tmp_path / "image.bin").write_bytes(DATA)
    (tmp_path / "aes.key").write_text(f"key={KEY}\niv={IV}\n")
    (tmp_path / "sw-description").write_text(
        'software = { version = "1.0"; images: ( %s ); files: ( %s ); }\n'
        % (", ".join(images), ", ".join(files))
    )
    swu = tmp_path / "out.swu"
    main.parse_args(
        ["-a", str(tmp_path), "-s", str(tmp_path / "sw-description"), "-o", str(swu),
         "-K", str(tmp_path / "aes.key"), "create"]
    )
    outdir = tmp_path / "extracted"
    with open(swu, "rb") as f:
        SWUFile(f).extract(str(outdir))
    swdesc = libconf.loads((outdir / "sw-description").read_text())
    return [
        (artifact, (outdir / artifact.filename).stat().st_size, outdir / artifact.filename)
        for section in ("images", "files")
        for artifact in swdesc.software.get(section, ())
    ]


def properties(artifact):
    return artifact.get("properties", {})


def checked_size(artifact, stored):
    """Size SWUpdate up to 2026.05.2 checks before copying an artifact
    to TMPDIR, as get_output_size(img, false): the stored size unless
    the property is set"""
    if artifact.get("compressed"):
        return int(properties(artifact).get("decompressed-size", stored))
    if artifact.get("encrypted"):
        return int(properties(artifact).get("decrypted-size", stored))
    return stored


def decrypted_length(path, artifact):
    return len(subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", KEY, "-iv", artifact.ivt,
         "-in", str(path)],
        check=True, capture_output=True,
    ).stdout)


def test_default_sizes(tmp_path):
    compressed, encrypted, both = create(
        tmp_path, [entry(COMPRESSED), entry(ENCRYPTED), entry(BOTH)]
    )
    assert properties(compressed[0])["decompressed-size"] == str(len(DATA))
    assert "decrypted-size" not in properties(compressed[0])

    assert properties(encrypted[0])["decrypted-size"] == str(len(DATA))
    assert "decompressed-size" not in properties(encrypted[0])

    assert properties(both[0])["decompressed-size"] == str(len(DATA))


def test_decrypted_size_is_below_stored_size(tmp_path):
    # read by SWUpdate only for an artifact that is not compressed
    ((artifact, stored, path),) = create(tmp_path, [entry(ENCRYPTED)])
    assert int(properties(artifact)["decrypted-size"]) == decrypted_length(path, artifact)
    assert int(properties(artifact)["decrypted-size"]) < stored


def test_staged_compressed_checked_for_original_size(tmp_path):
    # the issue that no-decompressed-size works around
    for artifact, stored, _ in create(tmp_path, [entry(COMPRESSED), entry(BOTH)]):
        assert checked_size(artifact, stored) == len(DATA) > stored


def test_no_decompressed_size(tmp_path):
    artifacts = create(
        tmp_path,
        [entry(COMPRESSED + " " + NO_SIZE), entry(BOTH + " " + NO_SIZE)],
        files=['{ filename = "image.bin"; path = "/tmp/x"; %s %s }'
               % (COMPRESSED, NO_SIZE)],
    )
    assert len(artifacts) == 3
    for artifact, stored, _ in artifacts:
        assert "decompressed-size" not in properties(artifact)
        assert checked_size(artifact, stored) <= stored
        # kept in sw-description, SWUpdate ignores it
        assert artifact["no-decompressed-size"] is True
    # decrypted-size is kept, it does not cause the issue
    assert "decrypted-size" in properties(artifacts[1][0])


def test_no_decompressed_size_only_for_its_entry(tmp_path):
    flagged, other = create(
        tmp_path, [entry(COMPRESSED + " " + NO_SIZE), entry(COMPRESSED)]
    )
    assert "decompressed-size" not in properties(flagged[0])
    assert properties(other[0])["decompressed-size"] == str(len(DATA))


def test_no_decompressed_size_false(tmp_path):
    ((artifact, _, _),) = create(
        tmp_path, [entry(COMPRESSED + " no-decompressed-size = false;")]
    )
    assert properties(artifact)["decompressed-size"] == str(len(DATA))


def test_no_decompressed_size_keeps_property_from_template(tmp_path):
    # for a handler that needs it, the property can be set by hand
    ((artifact, _, _),) = create(
        tmp_path,
        [entry(COMPRESSED + " " + NO_SIZE
               + ' properties: { decompressed-size = "1234"; };')],
    )
    assert properties(artifact)["decompressed-size"] == "1234"
