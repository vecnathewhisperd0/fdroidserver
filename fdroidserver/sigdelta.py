#!/usr/bin/env python3
#
# Copyright (C) 2017, Michael Poehn <michael.poehn@fsfe.org>
# Copyright (C) 2021 Felix C. Stegerman <flx@obfusk.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from argparse import ArgumentParser

import re
import os
import logging

from . import _
from . import common
from . import net
from .exception import FDroidException


def create_sigdelta(unsigned_apkpath, signed_apkpath):

    for apkpath in (unsigned_apkpath, signed_apkpath):
        if not os.path.exists(apkpath):
            raise FDroidException("file APK does not exists '{}'".format(apkpath))
    if not common.verify_apk_signature(signed_apkpath):
        raise FDroidException("no valid signature in '{}'".format(signed_apkpath))
    logging.debug('signature okay: %s', signed_apkpath)

    appid_u, vercode_u, _ignored = common.get_apk_id(unsigned_apkpath)
    appid_s, vercode_s, _ignored = common.get_apk_id(signed_apkpath)
    if appid_u != appid_s:      # FIXME
        raise FDroidException("unsigned and signed APK have different appid")
    if vercode_u != vercode_s:  # FIXME
        raise FDroidException("unsigned and signed APK have different version code")

    sigdir = common.metadata_get_sigdir(appid_s, vercode_s)
    if not os.path.exists(sigdir):
        os.makedirs(sigdir)
    common.apk_create_sigdelta(unsigned_apkpath, signed_apkpath, sigdir)

    return sigdir


def create(options):

    # Create tmp dir if missing…
    tmp_dir = 'tmp'
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)

    apks = dict(unsigned=options.unsigned_apk, signed=options.signed_apk)
    tmp_apks = []

    try:
        # download them…
        httpre = re.compile(r'https?:\/\/')
        for which, apk in tuple(apks.items()):
            try:
                if not os.path.isfile(apk) and httpre.match(apk):
                    if apk.startswith('https') or options.no_check_https:
                        tmp_apk = os.path.join(tmp_dir, which + '.apk')
                        net.download_file(apk, tmp_apk)
                        tmp_apks.append(tmp_apk)
                        apks[which] = tmp_apk
                    else:
                        logging.warning(_('refuse downloading via insecure HTTP connection '
                                          '(use HTTPS or specify --no-https-check): {apkfilename}')
                                        .format(apkfilename=apk))
                        return  # FIXME
            except FDroidException as e:
                logging.warning(_("Failed fetching signatures for '{apkfilename}': {error}")
                                .format(apkfilename=apk, error=e))
                if e.detail:
                    logging.debug(e.detail)

        # create sigdelta
        create_sigdelta(apks["unsigned"], apks["signed"])
    finally:
        for apk in tmp_apks:
            if apk and os.path.exists(apk):
                os.remove(apk)


def main():
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("unsigned_apk",
                        help=_("unsigned APK, either a file-path or HTTPS URL."))
    parser.add_argument("signed_apk",
                        help=_("signed APK, either a file-path or HTTPS URL."))
    parser.add_argument("--no-check-https", action="store_true", default=False)
    options = parser.parse_args()

    # Read config.py...
    common.read_config(options)

    create(options)
