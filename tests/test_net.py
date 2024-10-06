#!/usr/bin/env python3

import os
import random
import requests
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from fdroidserver import net
from pathlib import Path


class RetryServer:
    """A stupid simple HTTP server that can fail to connect"""

    def __init__(self, port=None, failures=3):
        self.port = port
        if self.port is None:
            self.port = random.randint(1024, 65535)  # nosec B311
        self.failures = failures
        self.stop_event = threading.Event()
        threading.Thread(target=self.run_fake_server).start()

    def stop(self):
        self.stop_event.set()

    def run_fake_server(self):
        server_sock = socket.socket()
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('127.0.0.1', self.port))
        server_sock.listen(5)
        server_sock.settimeout(5)
        time.sleep(0.001)  # wait for it to start

        while not self.stop_event.is_set():
            self.failures -= 1
            conn = None
            try:
                conn, address = server_sock.accept()
                conn.settimeout(5)
            except TimeoutError:
                break
            if self.failures > 0:
                conn.close()
                continue
            conn.recv(8192)  # request ignored
            self.reply = b"""HTTP/1.1 200 OK
                Date: Mon, 26 Feb 2024 09:00:14 GMT
                Connection: close
                Content-Type: text/html

                <HTML><BODY>Hello World!</HEAD></HTML>
                """
            self.reply = self.reply.replace(b'                ', b'')  # dedent
            conn.sendall(self.reply)
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()

            self.stop_event.wait(timeout=1)
        server_sock.shutdown(socket.SHUT_RDWR)
        server_sock.close()


class NetTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.chdir(self.tempdir.name)
        Path('tmp').mkdir()

    def tearDown(self):
        self.tempdir.cleanup()

    @patch('requests.get')
    def test_download_file_url_parsing(self, requests_get):
        # pylint: disable=unused-argument
        def _get(url, stream, allow_redirects, headers, timeout):
            return MagicMock()

        requests_get.side_effect = _get
        f = net.download_file('https://f-droid.org/repo/entry.jar', retries=0)
        requests_get.assert_called()
        self.assertTrue(os.path.exists(f))
        self.assertEqual('tmp/entry.jar', f)

        f = net.download_file(
            'https://d-05.example.com/custom/com.downloader.aegis-3175421.apk?_fn=QVBLUHVyZV92My4xNy41NF9hcGtwdXJlLmNvbS5hcGs&_p=Y29tLmFwa3B1cmUuYWVnb24&am=6avvTpfJ1dMl9-K6JYKzQw&arg=downloader%3A%2F%2Fcampaign%2F%3Futm_medium%3Ddownloader%26utm_source%3Daegis&at=1652080635&k=1f6e58465df3a441665e585719ab0b13627a117f&r=https%3A%2F%2Fdownloader.com%2Fdownloader-app.html%3Ficn%3Daegis%26ici%3Dimage_qr&uu=http%3A%2F%2F172.16.82.1%2Fcustom%2Fcom.downloader.aegis-3175421.apk%3Fk%3D3fb9c4ae0be578206f6a1c330736fac1627a117f',
            retries=0,
        )
        self.assertTrue(requests_get.called)
        self.assertTrue(os.path.exists(f))
        self.assertEqual('tmp/com.downloader.aegis-3175421.apk', f)

    def test_download_file_retries(self):
        server = RetryServer()
        f = net.download_file('http://localhost:%d/f.txt' % server.port)
        # strip the HTTP headers and compare the reply
        self.assertEqual(server.reply.split(b'\n\n')[1], Path(f).read_bytes())
        server.stop()

    def test_download_file_retries_not_forever(self):
        """The retry logic should eventually exit with an error."""
        server = RetryServer(failures=5)
        with self.assertRaises(requests.exceptions.ConnectionError):
            net.download_file('http://localhost:%d/f.txt' % server.port)
        server.stop()
