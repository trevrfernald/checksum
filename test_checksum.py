import unittest
from unittest.mock import patch
import checksum

# setUp / tearDown for files?
# https://youtu.be/6tNS--WetLI?t=1850
# ^ Python Tutorial: Unit Testing Your Code with the unittest Module

def test_choose_hash(self):
    self.assertEqual(choose_hash("sha256", file, checksum), )

def test_scan(self):
    pass # use mocking for testing data from a site
    with patch(requests.get) as mocked_get:
        mocked_get.return_value.ok = True
        mocked_get.return_value.text = True
