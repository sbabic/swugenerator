# pylint: disable=C0114,C0116,W0621
"""Tests for CMS signing with several signers and JSON sw-description"""
import hashlib
import json
import shutil
import subprocess

import pytest

from swugenerator import main
from swugenerator.swu_file import SWUFile
from swugenerator.swu_sign import SWUSignCMS, SWUSignRSA

ARTIFACT = b"payload of the artifact\n"


#### command line of openssl cms ####
def test_cms_single_signer_command_is_unchanged():
    sign = SWUSignCMS("key", "cert", "pass", "chain")
    sign.prepare_cmd("in", "out")
    assert sign.signcmd == [
        "openssl", "cms", "-sign", "-in", "in", "-out", "out", "-signer", "cert",
        "-inkey", "key", "-outform", "DER", "-nosmimecap", "-binary",
        "-passin", "file:pass", "-certfile", "chain",
    ]


def test_cms_several_signers_md_and_certfiles():
    sign = SWUSignCMS("k1", "c1", None, "chain1")
    sign.add_signer("k2", "c2", certfile="chain2")
    sign.add_certfile("chain3")
    sign.add_certfile("chain1")  # already there
    sign.set_md("sha512")
    sign.prepare_cmd("in", "out")
    assert sign.signcmd == [
        "openssl", "cms", "-sign", "-in", "in", "-out", "out", "-signer", "c1",
        "-inkey", "k1", "-signer", "c2", "-inkey", "k2", "-md", "sha512",
        "-outform", "DER", "-nosmimecap", "-binary",
        "-certfile", "chain1", "-certfile", "chain2", "-certfile", "chain3",
    ]


def test_cms_signers_share_the_password_file():
    sign = SWUSignCMS("k1", "c1", None, None)
    sign.add_signer("k2", "c2", passin="pass")
    assert sign.passin == "pass"
    sign.add_signer("k3", "c3", passin="pass")
    with pytest.raises(ValueError):
        sign.add_signer("k4", "c4", passin="other")


#### combination of -k options ####
def test_several_cms_options_are_one_signature():
    sign = main.parse_signing_options(
        ["CMS,k1,c1,pass", "CMS,k2,c2,,chain2"], cms_md="sha256", cms_certfiles=["chain3"]
    )
    assert isinstance(sign, SWUSignCMS)
    assert (sign.key, sign.cert) == ("k1", "c1")
    assert sign.signers == [("k2", "c2")]
    assert sign.md == "sha256"
    assert sign.certfiles == ["chain2", "chain3"]


def test_one_option_is_unchanged():
    sign = main.parse_signing_options(["RSA,key"])
    assert isinstance(sign, SWUSignRSA)
    assert sign.key == "key"


@pytest.mark.parametrize(
    "options,kwargs",
    [
        (["CMS,k1,c1", "RSA,key"], {}),
        (["RSA,k1", "RSA,k2"], {}),
        (["CMS,k1,c1,p1", "CMS,k2,c2,p2"], {}),
        (["RSA,key"], {"cms_md": "sha256"}),
        (["RSA,key"], {"cms_certfiles": ["chain"]}),
    ],
)
def test_invalid_combinations(options, kwargs):
    with pytest.raises(main.InvalidSigningOption):
        main.parse_signing_options(options, **kwargs)


def test_cms_options_need_cms(tmp_path):
    for extra in (["--cms-md", "sha256"], ["--cms-certfile", "chain"]):
        with pytest.raises(SystemExit):
            main.parse_args(["-s", "sw-description", "-o", str(tmp_path / "x.swu")]
                            + extra + ["create"])


#### end to end ####
def extract(swu, outdir):
    """Files of a SWU, in their order"""
    with open(swu, "rb") as f:
        SWUFile(f).extract(str(outdir))
    with open(swu, "rb") as f:
        data = f.read()
    names = []
    pos = 0
    while True:
        pos = data.find(b"070702", pos)
        if pos < 0:
            break
        namesize = int(data[pos + 94:pos + 102], 16)
        name = data[pos + 110:pos + 110 + namesize - 1].decode()
        if name == "TRAILER!!!":
            break
        names.append(name)
        filesize = int(data[pos + 54:pos + 62], 16)
        pos += 110 + namesize
        pos += -pos % 4 + filesize
    return names


@pytest.fixture()
def workdir(tmp_path):
    (tmp_path / "rootfs.img").write_bytes(ARTIFACT)
    (tmp_path / "extra.txt").write_bytes(b"not in sw-description\n")
    return tmp_path


LIBCONFIG = """software =
{
    version = "1.0";
    images: ( { filename = "rootfs.img"; device = "/dev/null"; type = "raw"; } );
}
"""


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_cms_with_two_signers(workdir):
    certs = []
    for n in ("1", "2"):
        key, cert = workdir / f"key{n}.pem", workdir / f"cert{n}.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key),
                        "-out", str(cert), "-subj", f"/CN=signer{n}", "-days", "1"],
                       check=True, capture_output=True)
        certs.append((key, cert))
    (workdir / "sw-description").write_text(LIBCONFIG)
    swu = workdir / "out.swu"
    main.parse_args(["-a", str(workdir), "-s", str(workdir / "sw-description"),
                     "-o", str(swu),
                     "-k", f"CMS,{certs[0][0]},{certs[0][1]}",
                     "-k", f"CMS,{certs[1][0]},{certs[1][1]}",
                     "--cms-md", "sha512", "create"])
    out = workdir / "extracted"
    out.mkdir()
    assert extract(swu, out) == ["sw-description", "sw-description.sig", "rootfs.img"]

    printed = subprocess.run(["openssl", "cms", "-cmsout", "-print", "-inform", "DER",
                              "-in", str(out / "sw-description.sig")],
                             check=True, capture_output=True, text=True).stdout
    # one SignerInfo for each signer, both with the digest given
    signer_infos = printed[printed.index("signerInfos:"):]
    assert signer_infos.count("d.issuerAndSerialNumber") == 2
    assert signer_infos.count("algorithm: sha512") == 2
    # both signatures verify (chain not checked: the certificates are self-signed)
    subprocess.run(["openssl", "cms", "-verify", "-inform", "DER", "-binary", "-noverify",
                    "-in", str(out / "sw-description.sig"),
                    "-content", str(out / "sw-description"), "-out", "/dev/null"],
                   check=True, capture_output=True)


def test_json_sw_description(workdir):
    template = {
        "software": {
            "version": "@@VERSION@@",
            "images": [{"filename": "rootfs.img", "device": "/dev/null", "type": "raw",
                        "size": "$swupdate_get_size(rootfs.img)"}],
        }
    }
    (workdir / "sw-description").write_text(json.dumps(template, indent=2))
    (workdir / "config").write_text('variables: { VERSION = "2.3"; };\n')
    swu = workdir / "out.swu"
    main.parse_args(["-a", str(workdir), "-s", str(workdir / "sw-description"),
                     "-c", str(workdir / "config"), "-o", str(swu), "create"])
    out = workdir / "extracted"
    out.mkdir()
    assert extract(swu, out) == ["sw-description", "rootfs.img"]
    swdesc = json.loads((out / "sw-description").read_text())
    image = swdesc["software"]["images"][0]
    assert swdesc["software"]["version"] == "2.3"
    assert image["sha256"] == hashlib.sha256(ARTIFACT).hexdigest()
    assert image["size"] == str(len(ARTIFACT))


def test_invalid_json_sw_description(workdir):
    (workdir / "sw-description").write_text('{ "software": { "version": "1.0", }')
    with pytest.raises(SystemExit):
        main.parse_args(["-a", str(workdir), "-s", str(workdir / "sw-description"),
                         "-o", str(workdir / "out.swu"), "create"])
    assert not (workdir / "out.swu").exists()
