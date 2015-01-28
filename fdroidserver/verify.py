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
import metadata
from zipfile import ZipFile
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

    verify_all(args)
    
def verify_all(args):

    verified = 0
    notverified = 0
    verified_apps = []
    not_verified_apps = []
    normal_apps = []

    allapps = metadata.read_metadata()
    vercodes = common.read_pkg_args(args, True)

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        logging.info("Creating temporary directory")
        os.makedirs(tmp_dir)

    unsigned_dir = 'unsigned'
    if not os.path.isdir(unsigned_dir):
        logging.error("No unsigned directory - nothing to do")
        sys.exit(0)
    # Process any apks that are waiting to be signed...    
    for apkfile in sorted(glob.glob(os.path.join(unsigned_dir, '*.apk'))):

        appid, vercode = common.apknameinfo(apkfile)
        apkfilename = os.path.basename(apkfile)
        if vercodes and appid not in vercodes:
            continue
        if appid in vercodes and vercodes[appid]:
            if vercode not in vercodes[appid]:
                continue
        logging.info("Processing " + apkfile)

        # There ought to be valid metadata for this app, otherwise why are we
        # trying to publish it?
        if appid not in allapps:
            logging.error("Unexpected {0} found in unsigned directory"
                          .format(apkfilename))
            sys.exit(1)
        app = allapps[appid]

        if app.get('Binaries', None):
            
            # It's an app where we build from source, and verify the apk
            # contents against a developer's binary, and then publish their
            # version if everything checks out.

            # Need the version name for the version code...
            versionname = None
            for build in app['builds']:
                if build['vercode'] == vercode:
                    versionname = build['version']
                    break
            if not versionname:
                logging.error("...no defined build for version code {0}"
                              .format(vercode))
                continue

            # Figure out where the developer's binary is supposed to come from...
            url = app['Binaries']
            url = url.replace('%v', versionname)
            url = url.replace('%c', str(vercode))

            # Grab the binary from where the developer publishes it...
            logging.info("...retrieving " + url)
            srcapk = os.path.join(tmp_dir, url.split('/')[-1])
            p = FDroidPopen(['wget', '-nv', '--continue', url], cwd=tmp_dir)
            if p.returncode != 0 or not os.path.exists(srcapk):
                logging.error("...failed to retrieve " + url +
                              " - publish skipped")
                continue

            # Compare our unsigned one with the downloaded one...
            verification_result = verify(srcapk, apkfile, tmp_dir)
            if verification_result is False:
                not_verified_apps.append(app)
                continue
            else:
                verified_apps.append(app)
        else:
            normal_apps.append(app)

    return (verified_apps, not_verified_apps, normal_apps)

def verify(official_apk, to_verify_apk, tmp_dir):
    
    with ZipFile(official_apk) as official_apk_as_zip:
        meta_inf_files = ['META-INF/MANIFEST.MF', 'META-INF/CERT.SF', 'META-INF/CERT.RSA']
        official_apk_as_zip.extractall(tmp_dir, meta_inf_files)
    with ZipFile(to_verify_apk, mode='a') as to_verify_apk_as_zip:
        for meta_inf_file in meta_inf_files:
            to_verify_apk_as_zip.write(os.path.join(tmp_dir, meta_inf_file), arcname=meta_inf_file)

    if subprocess.call(['jarsigner', '-verify', to_verify_apk]) != 0:
        logging.info("...NOT verified - {0}".format(to_verify_apk))
        common.compare_apks(official_apk, to_verify_apk, tmp_dir)
        return False
    else:
        logging.info("...successfully verified")
        return True

if __name__ == "__main__":
    main()
