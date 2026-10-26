# pylint: disable=C0114,C0116,W0621
"""Tests of the processing of sw-description"""
import pytest

from swugenerator.generator import SWUGenerator


@pytest.fixture()
def generator(tmp_path):
    (tmp_path / "image.bin").write_bytes(b"0123456789")
    gen = SWUGenerator(
        tmp_path / "sw-description", tmp_path / "out.swu", {}, [tmp_path], None, None, None
    )
    yield gen
    gen.abort()


@pytest.mark.parametrize(
    "line,expected",
    [
        ('size = "$swupdate_get_size(image.bin)";', 'size = "10";'),
        (
            'sha256 = "$swupdate_get_sha256(image.bin)";',
            'sha256 = "84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882";',
        ),
    ],
)
def test_functions(generator, line, expected):
    generator.lines = [line]
    generator._exec_functions()  # pylint: disable=protected-access
    assert generator.lines == [expected]


@pytest.mark.parametrize("function", ["swupdate_get_size", "swupdate_get_sha256"])
def test_functions_missing_artifact(generator, function):
    generator.lines = [f'value = "${function}(missing.bin)";']
    with pytest.raises(SystemExit):
        generator._exec_functions()  # pylint: disable=protected-access
