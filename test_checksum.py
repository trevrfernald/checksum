from checksum_gui import DataSet as a
import pytest

# setUp / tearDown for files?
# https://youtu.be/6tNS--WetLI?t=1850
# ^ Python Tutorial: Unit Testing Your Code with the unittest Module

# arrange, act, assert


@pytest.fixture
def instance(hash_function):
    checksum = "99D51AD7B1CC518082E7E73A56DE24DE249CD0D5090C78DAE87A591F96E081BA"
    return a.DataSet(hash_function, checksum, "C:/Users/T/Downloads/cmder.7z")


def test_calculate_checksum(instance):
    sha256_hash = "99D51AD7B1CC518082E7E73A56DE24DE249CD0D5090C78DAE87A591F96E081BA"
    assert a.calculate_checksum(instance(1)) == sha256_hash
    sha1_hash = "1080AD3A0083585AAE5B9D1D04C4A2AFCEBCB46D"
    assert a.calculate_checksum(instance(2)) == sha1_hash
    md5_hash = "fac349de98997a1e01caa77b2ecdb614"
    assert a.calculate_checksum(instance(3)) == md5_hash
