#!/usr/bin/env python3

import os
import unittest

import fdroidserver.common
import fdroidserver.install


@unittest.skipIf(
    os.getenv('CI_PROJECT_URL'),
    "skipping test_install, it's too troublesome in CI builds",
)
class InstallTest(unittest.TestCase):
    '''fdroidserver/install.py'''

    def test_devices(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        config['adb'] = fdroidserver.common.find_sdk_tools_cmd('adb')
        self.assertTrue(os.path.exists(config['adb']))
        self.assertTrue(os.path.isfile(config['adb']))
        devices = fdroidserver.install.devices()
        self.assertIsInstance(devices, list, 'install.devices() did not return a list!')
        for device in devices:
            self.assertIsInstance(device, str)
