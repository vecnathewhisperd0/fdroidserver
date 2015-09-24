#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# verify.py - part of the FDroid server tools
# Copyright (C) 2013, Ciaran Gultnieks, ciaran@ciarang.com
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import glob
from argparse import ArgumentParser
import logging

import common
import net
from common import FDroidException

options = None
config = None


def main():

    global options, config

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*', help="app-id with optional versioncode in the form APPID[:VERCODE]")
    options = parser.parse_args()

    config = common.read_config(options)

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        logging.info("Creating temporary directory")
        os.makedirs(tmp_dir)

    unsigned_dir = 'unsigned'
    if not os.path.isdir(unsigned_dir):
        logging.error("No unsigned directory - nothing to do")
        sys.exit(0)

    verified = 0
    notverified = 0

    vercodes = common.read_pkg_args(options.appid, True)

    for apkfile in sorted(glob.glob(os.path.join(unsigned_dir, '*.apk'))):

        apkfilename = os.path.basename(apkfile)
        appid, vercode = common.apknameinfo(apkfile)

        if vercodes and appid not in vercodes:
            continue
        if vercodes[appid] and vercode not in vercodes[appid]:
            continue

        try:

            logging.info("Processing " + apkfilename)

            remoteapk = os.path.join(tmp_dir, apkfilename)
            if os.path.exists(remoteapk):
                os.remove(remoteapk)
            url = 'https://f-droid.org/repo/' + apkfilename
            logging.info("...retrieving " + url)
            net.download_file(url, dldir=tmp_dir)

            compare_result = common.compare_apks(
                os.path.join(unsigned_dir, apkfilename),
                remoteapk,
                tmp_dir)
            if compare_result:
                raise FDroidException(compare_result)

            logging.info("...successfully verified")
            verified += 1

        except FDroidException as e:
            logging.info("...NOT verified - {0}".format(e))
            notverified += 1

    logging.info("Finished")
    logging.info("{0} successfully verified".format(verified))
    logging.info("{0} NOT verified".format(notverified))

if __name__ == "__main__":
    main()
