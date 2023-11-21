#!/usr/bin/env python3
#
# scanner.py - part of the FDroid server tools
# Copyright (C) 2010-13, Ciaran Gultnieks, ciaran@ciarang.com
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
import re
import sys
import json
import imghdr
import logging
import zipfile
import itertools
import traceback
import urllib.parse
import urllib.request
from argparse import ArgumentParser
from tempfile import TemporaryDirectory
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field, fields
from enum import IntEnum

from . import _
from . import common
from . import metadata
from .exception import BuildException, VCSException, ConfigurationException
from . import scanner

options = None


@dataclass
class MessageStore:
    infos: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


MAVEN_URL_REGEX = re.compile(r"""\smaven\s*(?:{.*?(?:setUrl|url)|\((?:url)?)\s*=?\s*(?:uri)?\(?\s*["']?([^\s"']+)["']?[^})]*[)}]""",
                             re.DOTALL)


SCANNER_CACHE_VERSION = 1


class ExitCode(IntEnum):
    NONFREE_CODE = 1


def get_gradle_compile_commands(build):
    compileCommands = ['compile',
                       'provided',
                       'apk',
                       'implementation',
                       'classpath',
                       'api',
                       'compileOnly',
                       'runtimeOnly']
    buildTypes = ['', 'release']
    flavors = ['']
    if build.gradle and build.gradle != ['yes']:
        flavors += build.gradle

    commands = [''.join(c) for c in itertools.product(flavors, buildTypes, compileCommands)]
    return [re.compile(r'\s*' + c, re.IGNORECASE) for c in commands]


def get_embedded_classes(apkfile, depth=0):
    """
    Get the list of Java classes embedded into all DEX files.

    :return: set of Java classes names as string
    """
    if depth > 10:  # zipbomb protection
        return {_('Max recursion depth in ZIP file reached: %s') % apkfile}

    archive_regex = re.compile(r'.*\.(aab|aar|apk|apks|jar|war|xapk|zip)$')
    class_regex = re.compile(r'classes.*\.dex')
    classes = set()

    try:
        with TemporaryDirectory() as tmp_dir, zipfile.ZipFile(apkfile, 'r') as apk_zip:
            for info in apk_zip.infolist():
                # apk files can contain apk files, again
                with apk_zip.open(info) as apk_fp:
                    if zipfile.is_zipfile(apk_fp):
                        classes = classes.union(get_embedded_classes(apk_fp, depth + 1))
                        if not archive_regex.search(info.filename):
                            classes.add(
                                'ZIP file without proper file extension: %s'
                                % info.filename
                            )
                        continue

                with apk_zip.open(info.filename) as fp:
                    file_magic = fp.read(3)
                if file_magic == b'dex':
                    if not class_regex.search(info.filename):
                        classes.add('DEX file with fake name: %s' % info.filename)
                    apk_zip.extract(info, tmp_dir)
                    run = common.SdkToolsPopen(
                        ["dexdump", '{}/{}'.format(tmp_dir, info.filename)],
                        output=False,
                    )
                    classes = classes.union(set(re.findall(r'[A-Z]+((?:\w+\/)+\w+)', run.output)))
    except zipfile.BadZipFile as ex:
        return {_('Problem with ZIP file: %s, error %s') % (apkfile, ex)}

    return classes


def _datetime_now():
    """Get datetime.now(), using this funciton allows mocking it for testing."""
    return datetime.utcnow()


def _scanner_cachedir():
    """Get `Path` to fdroidserver cache dir."""
    cfg = common.get_config()
    if not cfg:
        raise ConfigurationException('config not initialized')
    if "cachedir_scanner" not in cfg:
        raise ConfigurationException("could not load 'cachedir_scanner' from config")
    cachedir = Path(cfg["cachedir_scanner"])
    cachedir.mkdir(exist_ok=True, parents=True)
    return cachedir


class SignatureDataMalformedException(Exception):
    pass


class SignatureDataOutdatedException(Exception):
    pass


class SignatureDataCacheMissException(Exception):
    pass


class SignatureDataNoDefaultsException(Exception):
    pass


class SignatureDataVersionMismatchException(Exception):
    pass


class SignatureDataController:
    def __init__(self, name, filename, url):
        self.name = name
        self.filename = filename
        self.url = url
        # by default we assume cache is valid indefinitely
        self.cache_duration = timedelta(days=999999)
        self.data = {}

    def check_data_version(self):
        if self.data.get("version") != SCANNER_CACHE_VERSION:
            raise SignatureDataVersionMismatchException()

    def check_last_updated(self):
        """
        Check if the last_updated value is ok and raise an exception if expired or inaccessible.

        :raises SignatureDataMalformedException: when timestamp value is
                                                 inaccessible or not parse-able
        :raises SignatureDataOutdatedException: when timestamp is older then
                                                `self.cache_duration`
        """
        last_updated = self.data.get("last_updated", None)
        if last_updated:
            try:
                last_updated = datetime.fromtimestamp(last_updated)
            except ValueError as e:
                raise SignatureDataMalformedException() from e
            except TypeError as e:
                raise SignatureDataMalformedException() from e
            delta = (last_updated + self.cache_duration) - scanner._datetime_now()
            if delta > timedelta(seconds=0):
                logging.debug(_('next {name} cache update due in {time}').format(
                    name=self.filename, time=delta
                ))
            else:
                raise SignatureDataOutdatedException()

    def fetch(self):
        try:
            self.fetch_signatures_from_web()
            self.write_to_cache()
        except Exception as e:
            raise Exception(_("downloading scanner signatures from '{}' failed").format(self.url)) from e

    def load(self):
        try:
            try:
                self.load_from_cache()
                self.verify_data()
                self.check_last_updated()
            except SignatureDataCacheMissException:
                self.load_from_defaults()
        except (SignatureDataOutdatedException, SignatureDataNoDefaultsException):
            self.fetch_signatures_from_web()
            self.write_to_cache()
        except (SignatureDataMalformedException, SignatureDataVersionMismatchException) as e:
            logging.critical(_("scanner cache is malformed! You can clear it with: '{clear}'").format(
                clear='rm -r {}'.format(common.get_config()['cachedir_scanner'])
            ))
            raise e

    def load_from_defaults(self):
        raise SignatureDataNoDefaultsException()

    def load_from_cache(self):
        sig_file = scanner._scanner_cachedir() / self.filename
        if not sig_file.exists():
            raise SignatureDataCacheMissException()
        with open(sig_file) as f:
            self.set_data(json.load(f))

    def write_to_cache(self):
        sig_file = scanner._scanner_cachedir() / self.filename
        with open(sig_file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        logging.debug("write '{}' to cache".format(self.filename))

    def verify_data(self):
        """
        Clean and validate `self.data`.

        Right now this function does just a basic key sanitation.
        """
        self.check_data_version()
        valid_keys = ['timestamp', 'last_updated', 'version', 'signatures', 'cache_duration']

        for k in list(self.data.keys()):
            if k not in valid_keys:
                del self.data[k]

    def set_data(self, new_data):
        self.data = new_data
        if 'cache_duration' in new_data:
            self.cache_duration = timedelta(seconds=new_data['cache_duration'])

    def fetch_signatures_from_web(self):
        if not self.url.startswith("https://"):
            raise Exception(_("can't open non-https url: '{};".format(self.url)))
        logging.debug(_("downloading '{}'").format(self.url))
        with urllib.request.urlopen(self.url) as f:  # nosec B310 scheme filtered above
            self.set_data(json.load(f))
        self.data['last_updated'] = scanner._datetime_now().timestamp()


class ExodusSignatureDataController(SignatureDataController):
    def __init__(self):
        super().__init__('Exodus signatures', 'exodus.json', 'https://reports.exodus-privacy.eu.org/api/trackers')
        self.cache_duration = timedelta(days=1)  # refresh exodus cache after one day
        self.has_trackers_json_key = True

    def fetch_signatures_from_web(self):
        logging.debug(_("downloading '{}'").format(self.url))

        data = {
            "signatures": {},
            "timestamp": scanner._datetime_now().timestamp(),
            "last_updated": scanner._datetime_now().timestamp(),
            "version": SCANNER_CACHE_VERSION,
        }

        if not self.url.startswith("https://"):
            raise Exception(_("can't open non-https url: '{};".format(self.url)))
        with urllib.request.urlopen(self.url) as f:  # nosec B310 scheme filtered above
            trackerlist = json.load(f)
            if self.has_trackers_json_key:
                trackerlist = trackerlist["trackers"].values()
            for tracker in trackerlist:
                if tracker.get('code_signature'):
                    data["signatures"][tracker["name"]] = {
                        "name": tracker["name"],
                        "warn_code_signatures": [tracker["code_signature"]],
                        # exodus also provides network signatures, unused atm.
                        # "network_signatures": [tracker["network_signature"]],
                        "AntiFeatures": ["Tracking"],  # TODO
                        "license": "NonFree"  # We assume all trackers in exodus
                                              # are non-free, although free
                                              # trackers like piwik, acra,
                                              # etc. might be listed by exodus
                                              # too.
                    }
        self.set_data(data)


class EtipSignatureDataController(ExodusSignatureDataController):
    def __init__(self):
        super().__init__()
        self.name = 'ETIP signatures'
        self.filename = 'etip.json'
        self.url = 'https://etip.exodus-privacy.eu.org/api/trackers/?format=json'
        self.has_trackers_json_key = False


class SUSSDataController(SignatureDataController):
    def __init__(self):
        super().__init__(
            'SUSS',
            'suss.json',
            'https://fdroid.gitlab.io/fdroid-suss/suss.json'
        )

    def load_from_defaults(self):
        self.set_data(json.loads(SUSS_DEFAULT))


class ScannerTool():
    def __init__(self):

        # we could add support for loading additional signature source
        # definitions from config.yml here

        self.scanner_data_lookup()
        self.load()
        self.compile_regexes()

    def scanner_data_lookup(self):
        sigsources = common.get_config().get('scanner_signature_sources', [])
        logging.debug(
            "scanner is configured to use signature data from: '{}'"
            .format("', '".join(sigsources))
        )
        self.sdcs = []
        for i, source_url in enumerate(sigsources):
            if source_url.lower() == 'suss':
                self.sdcs.append(SUSSDataController())
            elif source_url.lower() == 'exodus':
                self.sdcs.append(ExodusSignatureDataController())
            elif source_url.lower() == 'etip':
                self.sdcs.append(EtipSignatureDataController())
            else:
                u = urllib.parse.urlparse(source_url)
                if u.scheme != 'https' or u.path == "":
                    raise ConfigurationException(
                        "Invalid 'scanner_signature_sources' configuration: '{}'. "
                        "Has to be a valid HTTPS-URL or match a predefined "
                        "constants: 'suss', 'exodus'".format(source_url)
                    )
                self.sdcs.append(SignatureDataController(
                    source_url,
                    '{}_{}'.format(i, os.path.basename(u.path)),
                    source_url,
                ))

    def load(self):
        for sdc in self.sdcs:
            sdc.load()

    def compile_regexes(self):
        self.regexs = {
            'err_code_signatures': {},
            'err_gradle_signatures': {},
            'warn_code_signatures': {},
            'warn_gradle_signatures': {},
        }
        for sdc in self.sdcs:
            for signame, sigdef in sdc.data.get('signatures', {}).items():
                for sig in sigdef.get('code_signatures', []):
                    self.regexs['err_code_signatures'][sig] = re.compile('.*' + sig, re.IGNORECASE)
                for sig in sigdef.get('gradle_signatures', []):
                    self.regexs['err_gradle_signatures'][sig] = re.compile('.*' + sig, re.IGNORECASE)
                for sig in sigdef.get('warn_code_signatures', []):
                    self.regexs['warn_code_signatures'][sig] = re.compile('.*' + sig, re.IGNORECASE)
                for sig in sigdef.get('warn_gradle_signatures', []):
                    self.regexs['warn_gradle_signatures'][sig] = re.compile('.*' + sig, re.IGNORECASE)

    def refresh(self):
        for sdc in self.sdcs:
            sdc.fetch_signatures_from_web()
            sdc.write_to_cache()

    def add(self, new_controller: SignatureDataController):
        self.sdcs.append(new_controller)
        self.compile_regexes()


# TODO: change this from singleton instance to dependency injection
# use `_get_tool()` instead of accessing this directly
_SCANNER_TOOL = None


def _get_tool():
    """
    Lazy loading function for getting a ScannerTool instance.

    ScannerTool initialization need to access `common.config` values. Those are only available after initialization through `common.read_config()`. So this factory assumes config was called at an erlier point in time.
    """
    if not scanner._SCANNER_TOOL:
        scanner._SCANNER_TOOL = ScannerTool()
    return scanner._SCANNER_TOOL


def scan_binary(apkfile):
    """Scan output of dexdump for known non-free classes."""
    logging.info(_('Scanning APK with dexdump for known non-free classes.'))
    result = get_embedded_classes(apkfile)
    problems, warnings = 0, 0
    for classname in result:
        for suspect, regexp in _get_tool().regexs['warn_code_signatures'].items():
            if regexp.match(classname):
                logging.debug("Warning: found class '%s'" % classname)
                warnings += 1
        for suspect, regexp in _get_tool().regexs['err_code_signatures'].items():
            if regexp.match(classname):
                logging.debug("Problem: found class '%s'" % classname)
                problems += 1
    if warnings:
        logging.warning(_("Found {count} warnings in {filename}").format(count=warnings, filename=apkfile))
    if problems:
        logging.critical(_("Found {count} problems in {filename}").format(count=problems, filename=apkfile))
    return problems


def scan_source(build_dir, build=metadata.Build(), json_per_build=None):
    """Scan the source code in the given directory (and all subdirectories).

    Returns
    -------
    the number of fatal problems encountered.
    """
    count = 0

    if not json_per_build:
        json_per_build = MessageStore()

    def suspects_found(s):
        for n, r in _get_tool().regexs['err_gradle_signatures'].items():
            if r.match(s):
                yield n

    allowed_repos = [re.compile(r'^https://' + re.escape(repo) + r'/*') for repo in [
        'repo1.maven.org/maven2',  # mavenCentral()
        'jcenter.bintray.com',     # jcenter()
        'jitpack.io',
        'www.jitpack.io',
        'repo.maven.apache.org/maven2',
        'oss.jfrog.org/artifactory/oss-snapshot-local',
        'oss.sonatype.org/content/repositories/snapshots',
        'oss.sonatype.org/content/repositories/releases',
        'oss.sonatype.org/content/groups/public',
        'oss.sonatype.org/service/local/staging/deploy/maven2',
        's01.oss.sonatype.org/content/repositories/snapshots',
        's01.oss.sonatype.org/content/repositories/releases',
        's01.oss.sonatype.org/content/groups/public',
        's01.oss.sonatype.org/service/local/staging/deploy/maven2',
        'clojars.org/repo',  # Clojure free software libs
        'repo.clojars.org',  # Clojure free software libs
        's3.amazonaws.com/repo.commonsware.com',  # CommonsWare
        'plugins.gradle.org/m2',  # Gradle plugin repo
        'maven.google.com',  # Google Maven Repo, https://developer.android.com/studio/build/dependencies.html#google-maven
        ]
    ] + [re.compile(r'^file://' + re.escape(repo) + r'/*') for repo in [
        '/usr/share/maven-repo',  # local repo on Debian installs
        ]
    ]

    scanignore = common.getpaths_map(build_dir, build.scanignore)
    scandelete = common.getpaths_map(build_dir, build.scandelete)

    scanignore_worked = set()
    scandelete_worked = set()

    def toignore(path_in_build_dir):
        for k, paths in scanignore.items():
            for p in paths:
                if path_in_build_dir.startswith(p):
                    scanignore_worked.add(k)
                    return True
        return False

    def todelete(path_in_build_dir):
        for k, paths in scandelete.items():
            for p in paths:
                if path_in_build_dir.startswith(p):
                    scandelete_worked.add(k)
                    return True
        return False

    def ignoreproblem(what, path_in_build_dir, json_per_build):
        """No summary.

        Parameters
        ----------
        what: string
          describing the problem, will be printed in log messages
        path_in_build_dir
          path to the file relative to `build`-dir

        Returns
        -------
        0 as we explicitly ignore the file, so don't count an error
        """
        msg = ('Ignoring %s at %s' % (what, path_in_build_dir))
        logging.info(msg)
        if json_per_build is not None:
            json_per_build.infos.append([msg, path_in_build_dir])
        return 0

    def removeproblem(what, path_in_build_dir, filepath, json_per_build):
        """No summary.

        Parameters
        ----------
        what: string
          describing the problem, will be printed in log messages
        path_in_build_dir
          path to the file relative to `build`-dir
        filepath
          Path (relative to our current path) to the file

        Returns
        -------
        0 as we deleted the offending file
        """
        msg = ('Removing %s at %s' % (what, path_in_build_dir))
        logging.info(msg)
        if json_per_build is not None:
            json_per_build.infos.append([msg, path_in_build_dir])
        try:
            os.remove(filepath)
        except FileNotFoundError:
            # File is already gone, nothing to do.
            # This can happen if we find multiple problems in one file that is setup for scandelete
            # I.e. build.gradle files containig multiple unknown maven repos.
            pass
        return 0

    def warnproblem(what, path_in_build_dir, json_per_build):
        """No summary.

        Parameters
        ----------
        what: string
          describing the problem, will be printed in log messages
        path_in_build_dir
          path to the file relative to `build`-dir

        Returns
        -------
        0, as warnings don't count as errors
        """
        if toignore(path_in_build_dir):
            return 0
        logging.warning('Found %s at %s' % (what, path_in_build_dir))
        if json_per_build is not None:
            json_per_build.warnings.append([what, path_in_build_dir])
        return 0

    def handleproblem(what, path_in_build_dir, filepath, json_per_build):
        """Dispatches to problem handlers (ignore, delete, warn).

        Or returns 1 for increasing the error count.

        Parameters
        ----------
        what: string
          describing the problem, will be printed in log messages
        path_in_build_dir
          path to the file relative to `build`-dir
        filepath
          Path (relative to our current path) to the file

        Returns
        -------
        0 if the problem was ignored/deleted/is only a warning, 1 otherwise
        """
        if toignore(path_in_build_dir):
            return ignoreproblem(what, path_in_build_dir, json_per_build)
        if todelete(path_in_build_dir):
            return removeproblem(what, path_in_build_dir, filepath, json_per_build)
        if 'src/test' in path_in_build_dir or '/test/' in path_in_build_dir:
            return warnproblem(what, path_in_build_dir, json_per_build)
        if options and 'json' in vars(options) and options.json:
            json_per_build.errors.append([what, path_in_build_dir])
        if options and (options.verbose or not ('json' in vars(options) and options.json)):
            logging.error('Found %s at %s' % (what, path_in_build_dir))
        return 1

    def is_executable(path):
        return os.path.exists(path) and os.access(path, os.X_OK)

    textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})

    def is_binary(path):
        d = None
        with open(path, 'rb') as f:
            d = f.read(1024)
        return bool(d.translate(None, textchars))

    # False positives patterns for files that are binary and executable.
    safe_paths = [re.compile(r) for r in [
        r".*/drawable[^/]*/.*\.png$",  # png drawables
        r".*/mipmap[^/]*/.*\.png$",    # png mipmaps
        ]
    ]

    def is_image_file(path):
        if imghdr.what(path) is not None:
            return True

    def safe_path(path_in_build_dir):
        for sp in safe_paths:
            if sp.match(path_in_build_dir):
                return True
        return False

    gradle_compile_commands = get_gradle_compile_commands(build)

    def is_used_by_gradle(line):
        return any(command.match(line) for command in gradle_compile_commands)

    # Iterate through all files in the source code
    for root, dirs, files in os.walk(build_dir, topdown=True):

        # It's topdown, so checking the basename is enough
        for ignoredir in ('.hg', '.git', '.svn', '.bzr'):
            if ignoredir in dirs:
                dirs.remove(ignoredir)

        for curfile in files:

            if curfile in ['.DS_Store']:
                continue

            # Path (relative) to the file
            filepath = os.path.join(root, curfile)

            if os.path.islink(filepath):
                continue

            path_in_build_dir = os.path.relpath(filepath, build_dir)

            if curfile in ('gradle-wrapper.jar', 'gradlew', 'gradlew.bat'):
                removeproblem(curfile, path_in_build_dir, filepath, json_per_build)
            elif curfile.endswith('.apk'):
                removeproblem(
                    _('Android APK file'), path_in_build_dir, filepath, json_per_build
                )

            elif curfile.endswith('.a'):
                count += handleproblem(
                    _('static library'), path_in_build_dir, filepath, json_per_build
                )
            elif curfile.endswith('.aar'):
                count += handleproblem(
                    _('Android AAR library'),
                    path_in_build_dir,
                    filepath,
                    json_per_build,
                )
            elif curfile.endswith('.class'):
                count += handleproblem(
                    _('Java compiled class'),
                    path_in_build_dir,
                    filepath,
                    json_per_build,
                )
            elif curfile.endswith('.dex'):
                count += handleproblem(
                    _('Android DEX code'), path_in_build_dir, filepath, json_per_build
                )
            elif curfile.endswith('.gz') or curfile.endswith('.tgz'):
                count += handleproblem(
                    _('gzip file archive'), path_in_build_dir, filepath, json_per_build
                )
            # We use a regular expression here to also match versioned shared objects like .so.0.0.0
            elif re.match(r'.*\.so(\..+)*$', curfile):
                count += handleproblem(
                    _('shared library'), path_in_build_dir, filepath, json_per_build
                )
            elif curfile.endswith('.zip'):
                count += handleproblem(
                    _('ZIP file archive'), path_in_build_dir, filepath, json_per_build
                )
            elif curfile.endswith('.jar'):
                for name in suspects_found(curfile):
                    count += handleproblem(
                        'usual suspect \'%s\'' % name,
                        path_in_build_dir,
                        filepath,
                        json_per_build,
                    )
                count += handleproblem(
                    _('Java JAR file'), path_in_build_dir, filepath, json_per_build
                )

            elif curfile.endswith('.java'):
                if not os.path.isfile(filepath):
                    continue
                with open(filepath, 'r', errors='replace') as f:
                    for line in f:
                        if 'DexClassLoader' in line:
                            count += handleproblem(
                                'DexClassLoader',
                                path_in_build_dir,
                                filepath,
                                json_per_build,
                            )
                            break

            elif curfile.endswith('.gradle') or curfile.endswith('.gradle.kts'):
                if not os.path.isfile(filepath):
                    continue
                with open(filepath, 'r', errors='replace') as f:
                    lines = f.readlines()
                for i, line in enumerate(lines):
                    if is_used_by_gradle(line):
                        for name in suspects_found(line):
                            count += handleproblem(
                                "usual suspect \'%s\'" % (name),
                                path_in_build_dir,
                                filepath,
                                json_per_build,
                            )
                noncomment_lines = [line for line in lines if not common.gradle_comment.match(line)]
                no_comments = re.sub(r'/\*.*?\*/', '', ''.join(noncomment_lines), flags=re.DOTALL)
                for url in MAVEN_URL_REGEX.findall(no_comments):
                    if not any(r.match(url) for r in allowed_repos):
                        count += handleproblem(
                            'unknown maven repo \'%s\'' % url,
                            path_in_build_dir,
                            filepath,
                            json_per_build,
                        )

            elif os.path.splitext(path_in_build_dir)[1] in ['', '.bin', '.out', '.exe']:
                if is_binary(filepath):
                    count += handleproblem(
                        'binary', path_in_build_dir, filepath, json_per_build
                    )

            elif is_executable(filepath):
                if is_binary(filepath) and not (safe_path(path_in_build_dir) or is_image_file(filepath)):
                    warnproblem(
                        _('executable binary, possibly code'),
                        path_in_build_dir,
                        json_per_build,
                    )

    for p in scanignore:
        if p not in scanignore_worked:
            logging.error(_('Unused scanignore path: %s') % p)
            count += 1

    for p in scandelete:
        if p not in scandelete_worked:
            logging.error(_('Unused scandelete path: %s') % p)
            count += 1

    return count


def get_argument_parser() -> ArgumentParser:
    parser = ArgumentParser(
        usage="%(prog)s [options] [(APPID[:VERCODE] | path/to.apk) ...]"
    )
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*', help=_("application ID with optional versionCode in the form APPID[:VERCODE]"))
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help=_("Force scan of disabled apps and builds."))
    parser.add_argument("--json", action="store_true", default=False,
                        help=_("Output JSON to stdout."))
    parser.add_argument("-r", "--refresh", action="store_true", default=False,
                        help=_("fetch the latest version of signatures from the web"))
    parser.add_argument("-e", "--exit-code", action="store_true", default=False,
                        help=_("Exit with a non-zero code if problems were found"))
    metadata.add_metadata_arguments(parser)
    return parser


def main():
    global options

    # Parse command line...
    options = get_argument_parser().parse_args()
    metadata.warnings_action = options.W

    json_output = dict()
    if options.json:
        if options.verbose:
            logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
        else:
            logging.getLogger().setLevel(logging.ERROR)

    # initialize/load configuration values
    common.get_config(opts=options)

    if options.refresh:
        scanner._get_tool().refresh()

    probcount = 0

    appids = []
    for apk in options.appid:
        if os.path.isfile(apk):
            count = scanner.scan_binary(apk)
            if count > 0:
                logging.warning(
                    _('Scanner found {count} problems in {apk}').format(
                        count=count, apk=apk
                    )
                )
                probcount += count
        else:
            appids.append(apk)

    if not appids:
        if options.exit_code and probcount > 0:
            sys.exit(ExitCode.NONFREE_CODE)
        return

    # Read all app and srclib metadata

    allapps = metadata.read_metadata()
    apps = common.read_app_args(appids, allapps, True)

    build_dir = 'build'
    if not os.path.isdir(build_dir):
        logging.info("Creating build directory")
        os.makedirs(build_dir)
    srclib_dir = os.path.join(build_dir, 'srclib')
    extlib_dir = os.path.join(build_dir, 'extlib')

    for appid, app in apps.items():

        json_per_appid = dict()

        if app.Disabled and not options.force:
            logging.info(_("Skipping {appid}: disabled").format(appid=appid))
            json_per_appid['disabled'] = MessageStore().infos.append(
                'Skipping: disabled'
            )
            continue

        try:
            if app.RepoType == 'srclib':
                build_dir = os.path.join('build', 'srclib', app.Repo)
            else:
                build_dir = os.path.join('build', appid)

            if app.get('Builds'):
                logging.info(_("Processing {appid}").format(appid=appid))
                # Set up vcs interface and make sure we have the latest code...
                vcs = common.getvcs(app.RepoType, app.Repo, build_dir)
            else:
                logging.info(_("{appid}: no builds specified, running on current source state")
                             .format(appid=appid))
                json_per_build = MessageStore()
                json_per_appid['current-source-state'] = json_per_build
                count = scan_source(build_dir, json_per_build=json_per_build)
                if count > 0:
                    logging.warning(_('Scanner found {count} problems in {appid}:')
                                    .format(count=count, appid=appid))
                    probcount += count
                app['Builds'] = []

            for build in app.get('Builds', []):
                json_per_build = MessageStore()
                json_per_appid[build.versionCode] = json_per_build

                if build.disable and not options.force:
                    logging.info("...skipping version %s - %s" % (
                        build.versionName, build.get('disable', build.commit[1:])))
                    continue

                logging.info("...scanning version " + build.versionName)
                # Prepare the source code...
                common.prepare_source(vcs, app, build,
                                      build_dir, srclib_dir,
                                      extlib_dir, False)

                count = scan_source(build_dir, build, json_per_build=json_per_build)
                if count > 0:
                    logging.warning(_('Scanner found {count} problems in {appid}:{versionCode}:')
                                    .format(count=count, appid=appid, versionCode=build.versionCode))
                    probcount += count

        except BuildException as be:
            logging.warning('Could not scan app %s due to BuildException: %s' % (
                appid, be))
            probcount += 1
        except VCSException as vcse:
            logging.warning('VCS error while scanning app %s: %s' % (appid, vcse))
            probcount += 1
        except Exception:
            logging.warning('Could not scan app %s due to unknown error: %s' % (
                appid, traceback.format_exc()))
            probcount += 1

        for k, v in json_per_appid.items():
            if len(v.errors) or len(v.warnings) or len(v.infos):
                json_output[appid] = {
                    k: dict((field.name, getattr(v, field.name)) for field in fields(v))
                    for k, v in json_per_appid.items()
                }
                break

    logging.info(_("Finished"))
    if options.json:
        print(json.dumps(json_output))
    else:
        print(_("%d problems found") % probcount)


if __name__ == "__main__":
    main()


SUSS_DEFAULT = '''{
  "cache_duration": 86400,
  "signatures": {
    "admob": {
      "gradle_signatures": [
        "admob.*sdk.*android"
      ],
      "license": "NonFree"
    },
    "androidx": {
      "gradle_signatures": [
        "androidx.navigation:navigation-dynamic-features",
        "androidx.work:work-gcm"
      ],
      "license": "NonFree"
    },
    "appcenter-push": {
      "gradle_signatures": [
        "appcenter-push"
      ],
      "license": "NonFree"
    },
    "bugsense": {
      "gradle_signatures": [
        "bugsense"
      ],
      "license": "NonFree"
    },
    "cloudrail": {
      "gradle_signatures": [
        "cloudrail"
      ],
      "license": "NonFree"
    },
    "com.android.billing": {
      "code_signatures": [
        "com/android/billing"
      ],
      "license": "NonFree"
    },
    "com.android.billingclient": {
      "gradle_signatures": [
        "com.android.billingclient"
      ],
      "license": "NonFree"
    },
    "com.anjlab.android.iab.v3": {
      "gradle_signatures": [
        "com.anjlab.android.iab.v3:library"
      ],
      "license": "NonFree"
    },
    "com.cloudinary": {
      "gradle_signatures": [
        "com.cloudinary:cloudinary-android"
      ],
      "license": "NonFree"
    },
    "com.evernote": {
      "gradle_signatures": [
        "com.evernote:android-job"
      ],
      "license": "NonFree"
    },
    "com.facebook": {
      "gradle_signatures": [
        "[\\"']com.facebook.android['\\":]"
      ],
      "license": "NonFree"
    },
    "com.github.junrar": {
      "gradle_signatures": [
        "com.github.junrar:junrar"
      ],
      "license": "NonFree"
    },
    "com.github.penn5": {
      "gradle_signatures": [
        "com.github.penn5:donations"
      ],
      "license": "NonFree"
    },
    "com.google.analytics": {
      "code_signatures": [
        "com/google/analytics"
      ],
      "license": "NonFree"
    },
    "com.google.android.exoplayer": {
      "gradle_signatures": [
        "com.google.android.exoplayer:extension-cast",
        "com.google.android.exoplayer:extension-cronet"
      ],
      "license": "NonFree"
    },
    "com.google.android.gms": {
      "code_signatures": [
        "com/google/android/gms"
      ],
      "license": "NonFree"
    },
    "com.google.android.libraries.places": {
      "gradle_signatures": [
        "com.google.android.libraries.places:places"
      ],
      "license": "NonFree"
    },
    "com.google.android.play": {
      "gradle_signatures": [
        "com.google.android.play:app-update",
        "com.google.android.play:core.*"
      ],
      "license": "NonFree"
    },
    "com.google.android.play.core": {
      "code_signatures": [
        "com/google/android/play/core"
      ],
      "license": "NonFree"
    },
    "com.google.firebase": {
      "code_signatures": [
        "com/google/firebase"
      ],
      "license": "NonFree"
    },
    "com.google.mlkit": {
      "gradle_signatures": [
        "com.google.mlkit"
      ],
      "license": "NonFree"
    },
    "com.google.tagmanager": {
      "code_signatures": [
        "com/google/tagmanager"
      ],
      "license": "NonFree"
    },
    "com.hypertrack": {
      "gradle_signatures": [
        "com\\\\.hypertrack(?!:hyperlog)"
      ],
      "license": "NonFree"
    },
    "com.mapbox": {
      "MaintainerNotes": "com.mapbox.mapboxsdk:mapbox-sdk-services seems to be fully under this license:\\nhttps://github.com/mapbox/mapbox-java/blob/main/LICENSE\\n",
      "gradle_signatures": [
        "com\\\\.mapbox(?!\\\\.mapboxsdk:mapbox-sdk-services)"
      ],
      "license": "NonFree"
    },
    "com.onesignal": {
      "gradle_signatures": [
        "com.onesignal:OneSignal"
      ],
      "license": "NonFree"
    },
    "com.tencent.bugly": {
      "gradle_signatures": [
        "com.tencent.bugly"
      ],
      "license": "NonFree"
    },
    "com.umeng.umsdk": {
      "gradle_signatures": [
        "com.umeng.umsdk"
      ],
      "license": "NonFree"
    },
    "com.yandex.android": {
      "gradle_signatures": [
        "com\\\\.yandex\\\\.android(?!:authsdk)"
      ],
      "license": "NonFree"
    },
    "com.yayandroid": {
      "gradle_signatures": [
        "com.yayandroid:LocationManager"
      ],
      "license": "NonFree"
    },
    "crashlytics": {
      "gradle_signatures": [
        "crashlytics"
      ],
      "license": "NonFree"
    },
    "crittercism": {
      "gradle_signatures": [
        "crittercism"
      ],
      "license": "NonFree"
    },
    "firebase": {
      "gradle_signatures": [
        "com(\\\\.google)?\\\\.firebase[.:](?!firebase-jobdispatcher|geofire-java)"
      ],
      "license": "NonFree"
    },
    "flurryagent": {
      "gradle_signatures": [
        "flurryagent"
      ],
      "license": "NonFree"
    },
    "google-ad": {
      "gradle_signatures": [
        "google.*ad.*view"
      ],
      "license": "NonFree"
    },
    "google.admob": {
      "gradle_signatures": [
        "google.*admob"
      ],
      "license": "NonFree"
    },
    "google.play.services": {
      "gradle_signatures": [
        "google.*play.*services"
      ],
      "license": "NonFree"
    },
    "heyzap": {
      "gradle_signatures": [
        "heyzap"
      ],
      "license": "NonFree"
    },
    "io.github.sinaweibosdk": {
      "gradle_signatures": [
        "io.github.sinaweibosdk"
      ],
      "license": "NonFree"
    },
    "io.objectbox": {
      "gradle_signatures": [
        "io.objectbox:objectbox-gradle-plugin"
      ],
      "license": "NonFree"
    },
    "jpct": {
      "gradle_signatures": [
        "jpct.*ae"
      ],
      "license": "NonFree"
    },
    "libspen23": {
      "gradle_signatures": [
        "libspen23"
      ],
      "license": "NonFree"
    },
    "me.pushy": {
      "gradle_signatures": [
        "me.pushy:sdk"
      ],
      "license": "NonFree"
    },
    "org.jetbrains.kotlinx": {
      "gradle_signatures": [
        "org.jetbrains.kotlinx:kotlinx-coroutines-play-services"
      ],
      "license": "NonFree"
    },
    "ouya": {
      "gradle_signatures": [
        "ouya.*sdk"
      ],
      "license": "NonFree"
    },
    "paypal": {
      "gradle_signatures": [
        "paypal.*mpl"
      ],
      "license": "NonFree"
    },
    "xyz.belvi.mobilevision": {
      "gradle_signatures": [
        "xyz.belvi.mobilevision:barcodescanner"
      ],
      "license": "NonFree"
    },
    "youtube": {
      "gradle_signatures": [
        "youtube.*android.*player.*api"
      ],
      "license": "NonFree"
    }
  },
  "timestamp": 1664480104.875586,
  "version": 1,
  "last_updated": 1664480104.875586
}'''
