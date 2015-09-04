#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# rewritemeta.py - part of the FDroid server tools
# This cleans up the original .txt metadata file format.
# Copyright (C) 2010-12, Ciaran Gultnieks, ciaran@ciarang.com
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

import os
from argparse import ArgumentParser
import logging
import common
import metadata

config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID [APPID ...]]")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    options = parser.parse_args()

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(xref=True)
    apps = common.read_app_args(args, allapps, False)

    for appid, app in apps.iteritems():
        metadatapath = app['metadatapath']
        ext = os.path.splitext(metadatapath)[1][1:]
        if ext == 'txt':
            logging.info("Rewriting " + metadatapath)
            metadata.write_metadata(metadatapath, app)
        else:
            logging.info("Ignoring %s file at '%s'"
                         % (ext.upper(), metadatapath))

    logging.info("Finished.")

if __name__ == "__main__":
    main()
