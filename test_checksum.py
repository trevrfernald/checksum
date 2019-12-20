from checksum_gui import DataSet
import pytest

# setUp / tearDown for files?
# https://youtu.be/6tNS--WetLI?t=1850
# ^ Python Tutorial: Unit Testing Your Code with the unittest Module

# arrange, act, assert


@pytest.fixture
def instance():
    checksum = "99D51AD7B1CC518082E7E73A56DE24DE249CD0D5090C78DAE87A591F96E081BA"
    return DataSet(1, "C:/Users/T/Downloads/cmder.7z", checksum)


def test_calculate_checksum(instance):
    sha256_hash = "99D51AD7B1CC518082E7E73A56DE24DE249CD0D5090C78DAE87A591F96E081BA".lower()
    assert DataSet.calculate_checksum(instance) == sha256_hash


def test_compare(instance):
    assert DataSet.compare(instance) is True


def scan(instance):
    pass  # need to use mocking here
