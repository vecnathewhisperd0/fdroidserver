#!/usr/bin/env python3

import unittest
from unittest.mock import patch

import fdroidserver


class ApiTest(unittest.TestCase):
    """Test the public API in the base "fdroidserver" module

    This is mostly a smokecheck to make sure the public API as
    declared in fdroidserver/__init__.py is working.  The functions
    are all implemented in other modules, with their own tests.

    """

    def test_download_repo_index_no_fingerprint(self):
        with self.assertRaises(fdroidserver.VerificationException):
            fdroidserver.download_repo_index("http://example.org")

    @patch('fdroidserver.net.http_get')
    def test_download_repo_index_url_parsing(self, mock_http_get):
        """Test whether it is trying to download the right file

        This passes the URL back via the etag return value just as a
        hack to check which URL was actually attempted.

        """
        mock_http_get.side_effect = lambda url, etag, timeout: (None, url)
        repo_url = 'https://example.org/fdroid/repo'
        index_url = 'https://example.org/fdroid/repo/index-v1.jar'
        for url in (repo_url, index_url):
            _ignored, etag_set_to_url = fdroidserver.download_repo_index(
                url, verify_fingerprint=False
            )
            self.assertEqual(index_url, etag_set_to_url)

    @patch('fdroidserver.net.http_get')
    def test_download_repo_index_v1_url_parsing(self, mock_http_get):
        """Test whether it is trying to download the right file

        This passes the URL back via the etag return value just as a
        hack to check which URL was actually attempted.

        """
        mock_http_get.side_effect = lambda url, etag, timeout: (None, url)
        repo_url = 'https://example.org/fdroid/repo'
        index_url = 'https://example.org/fdroid/repo/index-v1.jar'
        for url in (repo_url, index_url):
            _ignored, etag_set_to_url = fdroidserver.download_repo_index_v1(
                url, verify_fingerprint=False
            )
            self.assertEqual(index_url, etag_set_to_url)

    @patch('fdroidserver.net.http_get')
    def test_download_repo_index_v2_url_parsing(self, mock_http_get):
        """Test whether it is trying to download the right file

        This passes the URL back via the etag return value just as a
        hack to check which URL was actually attempted.

        """
        mock_http_get.side_effect = lambda url, etag, timeout: (None, url)
        repo_url = 'https://example.org/fdroid/repo'
        entry_url = 'https://example.org/fdroid/repo/entry.jar'
        index_url = 'https://example.org/fdroid/repo/index-v2.json'
        for url in (repo_url, entry_url, index_url):
            _ignored, etag_set_to_url = fdroidserver.download_repo_index_v2(
                url, verify_fingerprint=False
            )
            self.assertEqual(entry_url, etag_set_to_url)
