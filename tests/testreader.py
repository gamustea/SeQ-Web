import sys
import os

from unittest import TestCase
from src.misc.configread import ConfigReader


class TestReader(TestCase):

    def test_get_directory_of_valid_path(self):
        config_reader = ConfigReader()

        temp_dir = config_reader.get_directory_of("tempdir")
        temp_dir = config_reader.get_directory_of("logdir")
        temp_dir = config_reader.get_directory_of("resultdir")

        self.assertEqual(temp_dir, "/var/tmp/secapp")
        self.assertEqual(temp_dir, "/var/log/secapp")
        self.assertEqual(temp_dir, "/var/secapp/results")
        
    pass
