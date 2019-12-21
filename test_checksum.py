from checksum_gui import DataSet
import pytest

# arrange, act, assert
# implement checks and tests for valid path, key presence, checksum entry


@pytest.fixture(scope="module")
def instance():
    checksum = "99D51AD7B1CC518082E7E73A56DE24DE249CD0D5090C78DAE87A591F96E081BA"
    return DataSet(1, "C:/Users/T/Downloads/cmder.7z", checksum)
    print("teardown class instance")
    instance.close()


# @pytest.mark.parametrize(scope="module", params=[])
def test_calculate_checksum(instance):
    sha256_hash = "99D51AD7B1CC518082E7E73A56DE24DE249CD0D5090C78DAE87A591F96E081BA".lower()
    assert DataSet.calculate_checksum(instance) == sha256_hash


def test_compare(instance):
    print(instance.calculated_checksum)
    print(instance.checksum)
    assert DataSet.compare(instance) is True


def scan(instance):
    pass  # need to use mocking here
