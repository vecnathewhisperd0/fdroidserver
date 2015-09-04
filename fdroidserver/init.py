#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# update.py - part of the FDroid server tools
# Copyright (C) 2010-2013, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
# Copyright (C) 2013 Hans-Christoph Steiner <hans@eds.org>
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

import glob
import os
import re
import shutil
import socket
import sys
from argparse import ArgumentParser
import logging

import common

config = {}
options = None


def disable_in_config(key, value):
    '''write a key/value to the local config.py, then comment it out'''
    with open('config.py', 'r') as f:
        data = f.read()
    pattern = '\n[\s#]*' + key + '\s*=\s*"[^"]*"'
    repl = '\n#' + key + ' = "' + value + '"'
    data = re.sub(pattern, repl, data)
    with open('config.py', 'w') as f:
        f.writelines(data)


def main():

    global options, config

    # Parse command line...
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    parser.add_argument("-d", "--distinguished-name", default=None,
                      help="X.509 'Distiguished Name' used when generating keys")
    parser.add_argument("--keystore", default=None,
                      help="Path to the keystore for the repo signing key")
    parser.add_argument("--repo-keyalias", default=None,
                      help="Alias of the repo signing key in the keystore")
    parser.add_argument("--android-home", default=None,
                      help="Path to the Android SDK (sometimes set in ANDROID_HOME)")
    parser.add_argument("--no-prompt", action="store_true", default=False,
                      help="Do not prompt for Android SDK path, just fail")
    options = parser.parse_args()

    # find root install prefix
    tmp = os.path.dirname(sys.argv[0])
    if os.path.basename(tmp) == 'bin':
        prefix = None
        egg_link = os.path.join(tmp, '..', 'local/lib/python2.7/site-packages/fdroidserver.egg-link')
        if os.path.exists(egg_link):
            # installed from local git repo
            examplesdir = os.path.join(open(egg_link).readline().rstrip(), 'examples')
        else:
            prefix = os.path.dirname(os.path.dirname(__file__))  # use .egg layout
            if not prefix.endswith('.egg'):  # use UNIX layout
                prefix = os.path.dirname(tmp)
            examplesdir = prefix + '/share/doc/fdroidserver/examples'
    else:
        # we're running straight out of the git repo
        prefix = os.path.normpath(os.path.join(os.path.dirname(__file__), '..'))
        examplesdir = prefix + '/examples'

    aapt = None
    fdroiddir = os.getcwd()
    test_config = dict()
    common.fill_config_defaults(test_config)

    # track down where the Android SDK is, the default is to use the path set
    # in ANDROID_HOME if that exists, otherwise None
    if options.android_home is not None:
        test_config['sdk_path'] = options.android_home
    elif not common.test_sdk_exists(test_config):
        if os.path.isfile('/usr/bin/aapt'):
            # remove sdk_path and build_tools, they are not required
            test_config.pop('sdk_path', None)
            test_config.pop('build_tools', None)
            # make sure at least aapt is found, since this can't do anything without it
            test_config['aapt'] = common.find_sdk_tools_cmd('aapt')
        else:
            # if neither --android-home nor the default sdk_path exist, prompt the user
            default_sdk_path = '/opt/android-sdk'
            while not options.no_prompt:
                try:
                    s = raw_input('Enter the path to the Android SDK ('
                                  + default_sdk_path + ') here:\n> ')
                except KeyboardInterrupt:
                    print('')
                    sys.exit(1)
                if re.match('^\s*$', s) is not None:
                    test_config['sdk_path'] = default_sdk_path
                else:
                    test_config['sdk_path'] = s
                if common.test_sdk_exists(test_config):
                    break
    if not common.test_sdk_exists(test_config):
        sys.exit(3)

    if not os.path.exists('config.py'):
        # 'metadata' and 'tmp' are created in fdroid
        if not os.path.exists('repo'):
            os.mkdir('repo')
        shutil.copy(os.path.join(examplesdir, 'fdroid-icon.png'), fdroiddir)
        shutil.copyfile(os.path.join(examplesdir, 'config.py'), 'config.py')
        os.chmod('config.py', 0o0600)
        # If android_home is None, test_config['sdk_path'] will be used and
        # "$ANDROID_HOME" may be used if the env var is set up correctly.
        # If android_home is not None, the path given from the command line
        # will be directly written in the config.
        if 'sdk_path' in test_config:
            common.write_to_config(test_config, 'sdk_path', options.android_home)
    else:
        logging.warn('Looks like this is already an F-Droid repo, cowardly refusing to overwrite it...')
        logging.info('Try running `fdroid init` in an empty directory.')
        sys.exit()

    if 'aapt' not in test_config or not os.path.isfile(test_config['aapt']):
        # try to find a working aapt, in all the recent possible paths
        build_tools = os.path.join(test_config['sdk_path'], 'build-tools')
        aaptdirs = []
        aaptdirs.append(os.path.join(build_tools, test_config['build_tools']))
        aaptdirs.append(build_tools)
        for f in os.listdir(build_tools):
            if os.path.isdir(os.path.join(build_tools, f)):
                aaptdirs.append(os.path.join(build_tools, f))
        for d in sorted(aaptdirs, reverse=True):
            if os.path.isfile(os.path.join(d, 'aapt')):
                aapt = os.path.join(d, 'aapt')
                break
        if os.path.isfile(aapt):
            dirname = os.path.basename(os.path.dirname(aapt))
            if dirname == 'build-tools':
                # this is the old layout, before versioned build-tools
                test_config['build_tools'] = ''
            else:
                test_config['build_tools'] = dirname
            common.write_to_config(test_config, 'build_tools')
        common.ensure_build_tools_exists(test_config)

    # now that we have a local config.py, read configuration...
    config = common.read_config(options)

    # the NDK is optional and there may be multiple versions of it, so it's
    # left for the user to configure

    # find or generate the keystore for the repo signing key. First try the
    # path written in the default config.py.  Then check if the user has
    # specified a path from the command line, which will trump all others.
    # Otherwise, create ~/.local/share/fdroidserver and stick it in there.  If
    # keystore is set to NONE, that means that Java will look for keys in a
    # Hardware Security Module aka Smartcard.
    keystore = config['keystore']
    if options.keystore:
        keystore = os.path.abspath(options.keystore)
        if options.keystore == 'NONE':
            keystore = options.keystore
        else:
            keystore = os.path.abspath(options.keystore)
            if not os.path.exists(keystore):
                logging.info('"' + keystore
                             + '" does not exist, creating a new keystore there.')
    common.write_to_config(test_config, 'keystore', keystore)
    repo_keyalias = None
    if options.repo_keyalias:
        repo_keyalias = options.repo_keyalias
        common.write_to_config(test_config, 'repo_keyalias', repo_keyalias)
    if options.distinguished_name:
        keydname = options.distinguished_name
        common.write_to_config(test_config, 'keydname', keydname)
    if keystore == 'NONE':  # we're using a smartcard
        common.write_to_config(test_config, 'repo_keyalias', '1')  # seems to be the default
        disable_in_config('keypass', 'never used with smartcard')
        common.write_to_config(test_config, 'smartcardoptions',
                               ('-storetype PKCS11 -providerName SunPKCS11-OpenSC '
                                + '-providerClass sun.security.pkcs11.SunPKCS11 '
                                + '-providerArg opensc-fdroid.cfg'))
        # find opensc-pkcs11.so
        if not os.path.exists('opensc-fdroid.cfg'):
            if os.path.exists('/usr/lib/opensc-pkcs11.so'):
                opensc_so = '/usr/lib/opensc-pkcs11.so'
            elif os.path.exists('/usr/lib64/opensc-pkcs11.so'):
                opensc_so = '/usr/lib64/opensc-pkcs11.so'
            else:
                files = glob.glob('/usr/lib/' + os.uname()[4] + '-*-gnu/opensc-pkcs11.so')
                if len(files) > 0:
                    opensc_so = files[0]
                else:
                    opensc_so = '/usr/lib/opensc-pkcs11.so'
                    logging.warn('No OpenSC PKCS#11 module found, ' +
                                 'install OpenSC then edit "opensc-fdroid.cfg"!')
            with open(os.path.join(examplesdir, 'opensc-fdroid.cfg'), 'r') as f:
                opensc_fdroid = f.read()
            opensc_fdroid = re.sub('^library.*', 'library = ' + opensc_so, opensc_fdroid,
                                   flags=re.MULTILINE)
            with open('opensc-fdroid.cfg', 'w') as f:
                f.write(opensc_fdroid)
    elif not os.path.exists(keystore):
        password = common.genpassword()
        c = dict(test_config)
        c['keystorepass'] = password
        c['keypass'] = password
        c['repo_keyalias'] = socket.getfqdn()
        c['keydname'] = 'CN=' + c['repo_keyalias'] + ', OU=F-Droid'
        common.write_to_config(test_config, 'keystorepass', password)
        common.write_to_config(test_config, 'keypass', password)
        common.write_to_config(test_config, 'repo_keyalias', c['repo_keyalias'])
        common.write_to_config(test_config, 'keydname', c['keydname'])
        common.genkeystore(c)

    logging.info('Built repo based in "' + fdroiddir + '"')
    logging.info('with this config:')
    logging.info('  Android SDK:\t\t\t' + config['sdk_path'])
    if aapt:
        logging.info('  Android SDK Build Tools:\t' + os.path.dirname(aapt))
    logging.info('  Android NDK r10e (optional):\t$ANDROID_NDK')
    logging.info('  Keystore for signing key:\t' + keystore)
    if repo_keyalias is not None:
        logging.info('  Alias for key in store:\t' + repo_keyalias)
    logging.info('\nTo complete the setup, add your APKs to "' +
                 os.path.join(fdroiddir, 'repo') + '"' + '''
then run "fdroid update -c; fdroid update".  You might also want to edit
"config.py" to set the URL, repo name, and more.  You should also set up
a signing key (a temporary one might have been automatically generated).

For more info: https://f-droid.org/manual/fdroid.html#Simple-Binary-Repository
and https://f-droid.org/manual/fdroid.html#Signing
''')
