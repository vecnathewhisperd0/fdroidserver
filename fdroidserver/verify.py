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
from optparse import OptionParser
import logging

import common
from common import FDroidPopen, FDroidException
import subprocess
from zipfile import ZipFile
from pdb import set_trace
options = None
config = None


def main():

    global options, config

    # Parse command line...
    parser = OptionParser(usage="Usage: %prog [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    (options, args) = parser.parse_args()

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

    vercodes = common.read_pkg_args(args, True)

    for apkfile in sorted(glob.glob(os.path.join(unsigned_dir, '*.apk'))):

        apkfilename = os.path.basename(apkfile)
        appid, vercode = common.apknameinfo(apkfile)

        if vercodes and appid not in vercodes:
            continue

        if vercodes[appid] and vercode not in vercodes[appid]:
            continue

        logging.info("Processing " + apkfilename)
        official_apk = os.path.join(tmp_dir, apkfilename)
        fdroid_apk = os.path.join(unsigned_dir, apkfilename)
        verify(official_apk, fdroid_apk, tmp_dir)
            
def verify(official_apk, to_verify_apk, tmp_dir):
    
    with ZipFile(official_apk) as official_apk_as_zip:
        meta_inf_files = ['META-INF/MANIFEST.MF', 'META-INF/CERT.SF', 'META-INF/CERT.RSA']
        official_apk_as_zip.extractall(tmp_dir, meta_inf_files)
    with ZipFile(to_verify_apk, mode='a') as to_verify_apk_as_zip:
        for meta_inf_file in meta_inf_files:
            to_verify_apk_as_zip.write(os.path.join(tmp_dir, meta_inf_file), arcname=meta_inf_file)

    if subprocess.call(['jarsigner', '-verify', to_verify_apk]) != 0:
        logging.info("...NOT verified - {0}".format(to_verify_apk))
        
        return False
    else:
        logging.info("...successfully verified")
        return True

if __name__ == "__main__":
    main()
