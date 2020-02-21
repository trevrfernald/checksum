from checksum_gui import DataSet
import pytest
from unittest.mock import Mock, patch


@pytest.fixture
@patch("checksum_gui.DataSet.calculate_checksum", return_value="aaa")
def instance(mock_calculate_checksum):
    path_mock = Mock()
    return DataSet(1, path_mock, "aaa")


def test_calculate_checksum(instance):
    assert instance.calculated_checksum == "aaa"


def test_compare(instance):
    assert DataSet.compare(instance) is True


def test_scan(instance):
    with patch("requests.get") as mock_get:
        mock_get.return_value.ok = True
        response = DataSet.scan(instance)
    assert response is not None


def test_scan_with_data(instance):
    mock_get_patcher = patch('requests.get')
    mock_get = mock_get_patcher.start()
    data = {
        'response_code': 1,
        'verbose_msg': 'Scan finished',
        'permalink': 'https://www.virustotal.com/file/',
        'positives': 2,
        'total': 60
        }

    mock_get.return_value = Mock(ok=True)
    mock_get.return_value.json.return_value = data

    response = DataSet.scan(instance)
    mock_get = mock_get_patcher.stop()

    assert response == data

# def test_IOError():
#     with pytest.raises(IOError):
#         DataSet(1, 'file.txt', checksum)
