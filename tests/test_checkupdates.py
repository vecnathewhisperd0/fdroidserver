#!/usr/bin/env python3

import unittest
from unittest import mock
from pathlib import Path

import fdroidserver
import fdroidserver.checkupdates


class CheckupdatesTest(unittest.TestCase):
    '''fdroidserver/checkupdates.py'''

    def test_autoupdatemode_no_suffix(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersion = '1.1.8-fdroid'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.AutoUpdateMode = 'Version %v'

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode
        build.versionName = app.CurrentVersion
        app['Builds'].append(build)

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: ('1.1.9', 10109)
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.commit, '1.1.9')

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: ('1.7.9', 10107)
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    with self.assertRaises(fdroidserver.exception.FDroidException):
                        fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.commit, '1.1.9')

    def test_autoupdatemode_suffix(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersion = '1.1.8-fdroid'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.AutoUpdateMode = r'Version +.%c-fdroid v%v_%c'

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode
        build.versionName = app.CurrentVersion
        app['Builds'].append(build)

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: ('1.1.9', 10109)
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9.10109-fdroid')
        self.assertEqual(build.commit, 'v1.1.9_10109')

    def test_autoupdate_multi_variants(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersion = '1.1.8'
        app.CurrentVersionCode = 101083
        app.UpdateCheckMode = 'Tags'
        app.AutoUpdateMode = r'Version'
        app.VercodeOperation = [
            "10*%c+1",
            "10*%c+3",
        ]

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode - 2
        build.versionName = app.CurrentVersion
        build.gradle = ["arm"]
        app['Builds'].append(build)

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode
        build.versionName = app.CurrentVersion
        build.gradle = ["x86"]
        app['Builds'].append(build)

        with mock.patch(
            'fdroidserver.checkupdates.check_tags',
            lambda app, pattern: ('1.1.9', 10109, 'v1.1.9'),
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-2]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.versionCode, 101091)
        self.assertEqual(build.gradle, ["arm"])

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.versionCode, 101093)
        self.assertEqual(build.gradle, ["x86"])

        self.assertEqual(app.CurrentVersion, '1.1.9')
        self.assertEqual(app.CurrentVersionCode, 101093)

    def test_checkupdates_app_http(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.UpdateCheckData = 'mock'

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: (None, 'bla')
        ):
            with self.assertRaises(fdroidserver.exception.FDroidException):
                fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: ('1.1.9', 10109)
        ):
            with mock.patch(
                'fdroidserver.metadata.write_metadata', mock.Mock()
            ) as wrmock:
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)
                wrmock.assert_called_with(app.metadatapath, app)

    def test_checkupdates_app_tags(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersion = '1.1.8'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'Tags'
        app.AutoUpdateMode = 'Version'

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode
        build.versionName = app.CurrentVersion
        app['Builds'].append(build)

        with mock.patch(
            'fdroidserver.checkupdates.check_tags',
            lambda app, pattern: (None, 'bla', None),
        ):
            with self.assertRaises(fdroidserver.exception.FDroidException):
                fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        with mock.patch(
            'fdroidserver.checkupdates.check_tags',
            lambda app, pattern: ('1.1.9', 10109, 'v1.1.9'),
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.commit, 'v1.1.9')

    def test_check_http(self):
        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.UpdateCheckData = r'https://a.net/b.txt|c(.*)|https://d.net/e.txt|v(.*)'
        app.UpdateCheckIgnore = 'beta'

        respmock = mock.Mock()
        respmock.read = lambda: 'v1.1.9\nc10109'.encode('utf-8')
        with mock.patch('urllib.request.urlopen', lambda a, b, c: respmock):
            vername, vercode = fdroidserver.checkupdates.check_http(app)
        self.assertEqual(vername, '1.1.9')
        self.assertEqual(vercode, 10109)

    def test_check_http_blocks_unknown_schemes(self):
        app = fdroidserver.metadata.App()
        for scheme in ('file', 'ssh', 'http', ';pwn'):
            app.id = scheme
            faked = scheme + '://fake.url/for/testing/scheme'
            app.UpdateCheckData = faked + '|ignored|' + faked + '|ignored'
            app.metadatapath = 'metadata/' + app.id + '.yml'
            with self.assertRaises(fdroidserver.exception.FDroidException):
                fdroidserver.checkupdates.check_http(app)

    def test_check_http_ignore(self):
        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.UpdateCheckData = r'https://a.net/b.txt|c(.*)|https://d.net/e.txt|v(.*)'
        app.UpdateCheckIgnore = 'beta'

        respmock = mock.Mock()
        respmock.read = lambda: 'v1.1.9-beta\nc10109'.encode('utf-8')
        with mock.patch('urllib.request.urlopen', lambda a, b, c: respmock):
            vername, vercode = fdroidserver.checkupdates.check_http(app)
        self.assertEqual(vername, None)

    def test_check_tags_data(self):
        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.RepoType = 'git'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'Tags'
        app.UpdateCheckData = r'b.txt|c(.*)|e.txt|v(.*)'

        vcs = mock.Mock()
        vcs.latesttags.return_value = ['1.1.9', '1.1.8']
        with mock.patch(
            'pathlib.Path.read_text', lambda a: 'v1.1.9\nc10109'
        ) as _ignored, mock.patch.object(
            Path, 'is_file'
        ) as mock_path, mock.patch('fdroidserver.common.getvcs', return_value=vcs):
            _ignored  # silence the linters
            mock_path.is_file.return_falue = True
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.9')
        self.assertEqual(vercode, 10109)

        app.UpdateCheckData = r'b.txt|c(.*)|.|v(.*)'
        with mock.patch(
            'pathlib.Path.read_text', lambda a: 'v1.1.0\nc10109'
        ) as _ignored, mock.patch.object(
            Path, 'is_file'
        ) as mock_path, mock.patch('fdroidserver.common.getvcs', return_value=vcs):
            _ignored  # silence the linters
            mock_path.is_file.return_falue = True
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.0')
        self.assertEqual(vercode, 10109)

        app.UpdateCheckData = r'b.txt|c(.*)||'
        with mock.patch(
            'pathlib.Path.read_text', lambda a: 'v1.1.9\nc10109'
        ) as _ignored, mock.patch.object(
            Path, 'is_file'
        ) as mock_path, mock.patch('fdroidserver.common.getvcs', return_value=vcs):
            _ignored  # silence the linters
            mock_path.is_file.return_falue = True
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.9')
        self.assertEqual(vercode, 10109)

        vcs.latesttags.return_value = ['Android-1.1.0', '1.1.8']
        app.UpdateCheckData = r'b.txt|c(.*)||Android-([\d.]+)'
        with mock.patch(
            'pathlib.Path.read_text', lambda a: 'v1.1.9\nc10109'
        ) as _ignored, mock.patch.object(
            Path, 'is_file'
        ) as mock_path, mock.patch('fdroidserver.common.getvcs', return_value=vcs):
            _ignored  # silence the linters
            mock_path.is_file.return_falue = True
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.0')
        self.assertEqual(vercode, 10109)

        app.UpdateCheckData = r'|\+(\d+)||Android-([\d.]+)'
        vcs.latesttags.return_value = ['Android-1.1.0+1']
        with mock.patch('fdroidserver.common.getvcs', return_value=vcs):
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.0')
        self.assertEqual(vercode, 1)

        app.UpdateCheckData = '|||'
        vcs.latesttags.return_value = ['2']
        with mock.patch('fdroidserver.common.getvcs', return_value=vcs):
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '2')
        self.assertEqual(vercode, 2)
