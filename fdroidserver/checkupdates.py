#!/usr/bin/env python3
#
# checkupdates.py - part of the FDroid server tools
# Copyright (C) 2010-2015, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
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

import copy
import html
import logging
import os
import re
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from argparse import ArgumentParser
from distutils.version import LooseVersion

from . import _
from . import common
from . import metadata
from . import net
from .exception import VCSException, NoSubmodulesException, FDroidException, MetaDataException


def check_http(app):
    """
    Check for a new version by looking at a document retrieved via HTTP.
    The app's Update Check Data field is used to provide the information
    required.
    """
    ignore_versions = app.UpdateCheckIgnore
    ignore_search = re.compile(ignore_versions).search if ignore_versions else None

    try:

        if not app.UpdateCheckData:
            raise FDroidException('Missing Update Check Data')

        url_code, code_ex, url_ver, ver_ex = app.UpdateCheckData.split('|')
        parsed = urllib.parse.urlparse(url_code)
        if not parsed.netloc or not parsed.scheme or parsed.scheme != 'https':
            raise FDroidException(_('UpdateCheckData has invalid URL: {url}').format(url=url_code))
        if url_ver != '.':
            parsed = urllib.parse.urlparse(url_ver)
            if not parsed.netloc or not parsed.scheme or parsed.scheme != 'https':
                raise FDroidException(_('UpdateCheckData has invalid URL: {url}').format(url=url_code))

        ver_code = None
        if len(url_code) > 0:
            logging.debug("...requesting {0}".format(url_code))
            req = urllib.request.Request(url_code, None, headers=net.HEADERS)
            resp = urllib.request.urlopen(req, None, 20)  # nosec B310 scheme is filtered above
            page = resp.read().decode('utf-8')

            m = re.search(code_ex, page)
            if not m:
                raise FDroidException("No RE match for version code")
            ver_code = m.group(1).strip()

        version = "??"
        if len(url_ver) > 0:
            if url_ver != '.':
                logging.debug("...requesting {0}".format(url_ver))
                req = urllib.request.Request(url_ver, None)
                resp = urllib.request.urlopen(req, None, 20)  # nosec B310 scheme is filtered above
                page = resp.read().decode('utf-8')

            m = re.search(ver_ex, page)
            if not m:
                raise FDroidException("No RE match for version")
            version = m.group(1)

        if ignore_search and version:
            if not ignore_search(version):
                return version, ver_code
            else:
                return None, "Version {version} is ignored".format(version=version)
        else:
            return version, ver_code
    except FDroidException:
        msg = "Could not complete http check for app {0} due to unknown error: {1}".format(app.id,
                                                                                           traceback.format_exc())
        return None, msg


def check_tags(app, pattern):
    """
    Check for a new version by looking at the tags in the source repo.
    Whether this can be used reliably or not depends on
    the development procedures used by the project's developers. Use it with
    caution, because it's inappropriate for many projects.
    Returns (None, "a message") if this didn't work, or (version, versionCode, tag) for
    the details of the current version.
    """
    try:

        if app.RepoType == 'srclib':
            build_dir = os.path.join('build', 'srclib', app.Repo)
            repo_type = common.get_srclib_vcs(app.Repo)
        else:
            build_dir = os.path.join('build', app.id)
            repo_type = app.RepoType

        if repo_type not in ('git', 'git-svn', 'hg', 'bzr'):
            return None, 'Tags update mode only works for git, hg, bzr and git-svn repositories currently', None

        if repo_type == 'git-svn' and ';' not in app.Repo:
            return None, 'Tags update mode used in git-svn, but the repo was not set up with tags', None

        # Set up vcs interface and make sure we have the latest code...
        vcs = common.get_vcs(app.RepoType, app.Repo, build_dir)

        vcs.go_to_revision(None)

        last_build = app.get_last_build()

        try_init_submodules(app, last_build, vcs)

        h_pak = None
        h_tag = None
        h_ver = None
        h_code = "0"

        if repo_type == 'git':
            tags = vcs.latest_tags()
        else:
            tags = vcs.gettags()
        if not tags:
            return None, "No tags found", None

        logging.debug("All tags: " + ','.join(tags))
        if pattern:
            pat = re.compile(pattern)
            tags = [tag for tag in tags if pat.match(tag)]
            if not tags:
                return None, "No matching tags found", None
            logging.debug("Matching tags: " + ','.join(tags))

        if len(tags) > 5 and repo_type == 'git':
            tags = tags[:5]
            logging.debug("Latest tags: " + ','.join(tags))

        for tag in tags:
            logging.debug("Check tag: '{0}'".format(tag))
            vcs.go_to_revision(tag)

            for subdir in possible_subdirs(app):
                if subdir == '.':
                    root_dir = build_dir
                else:
                    root_dir = os.path.join(build_dir, subdir)
                paths = common.manifest_paths(root_dir, last_build.gradle)
                version, ver_code, package = common.parse_android_manifests(paths, app)
                if ver_code:
                    logging.debug("Manifest exists in subdir '{0}'. Found version {1} ({2})"
                                  .format(subdir, version, ver_code))
                    i_ver_code = common.version_code_string_to_int(ver_code)
                    if i_ver_code > common.version_code_string_to_int(h_code):
                        h_pak = package
                        h_tag = tag
                        h_code = str(i_ver_code)
                        h_ver = version

        if not h_pak:
            return None, "Couldn't find package ID", None
        if h_ver:
            return h_ver, h_code, h_tag
        return None, "Couldn't find any version information", None

    except VCSException as vcse:
        msg = "VCS error while scanning app {0}: {1}".format(app.id, vcse)
        return None, msg, None
    except Exception:
        msg = "Could not scan app {0} due to unknown error: {1}".format(app.id, traceback.format_exc())
        return None, msg, None


def check_repo_manifest(app, branch=None):
    """
    Check for a new version by looking at the AndroidManifest.xml at the HEAD
    of the source repo. Whether this can be used reliably or not depends on
    the development procedures used by the project's developers. Use it with
    caution, because it's inappropriate for many projects.
    Returns (None, "a message") if this didn't work, or (version, versionCode) for
    the details of the current version.
    """
    try:

        if app.RepoType == 'srclib':
            build_dir = os.path.join('build', 'srclib', app.Repo)
            repo_type = common.get_srclib_vcs(app.Repo)
        else:
            build_dir = os.path.join('build', app.id)
            repo_type = app.RepoType

        # Set up vcs interface and make sure we have the latest code...
        vcs = common.get_vcs(app.RepoType, app.Repo, build_dir)

        if repo_type == 'git':
            if branch:
                branch = 'origin/' + branch
            vcs.go_to_revision(branch)
        elif repo_type == 'git-svn':
            vcs.go_to_revision(branch)
        elif repo_type == 'hg':
            vcs.go_to_revision(branch)
        elif repo_type == 'bzr':
            vcs.go_to_revision(None)

        last_build = metadata.Build()
        if len(app.get('Builds', [])) > 0:
            last_build = app.get('Builds', [])[-1]

        try_init_submodules(app, last_build, vcs)

        h_pak = None
        h_ver = None
        h_code = "0"
        for subdir in possible_subdirs(app):
            if subdir == '.':
                root_dir = build_dir
            else:
                root_dir = os.path.join(build_dir, subdir)
            paths = common.manifest_paths(root_dir, last_build.gradle)
            version, ver_code, package = common.parse_android_manifests(paths, app)
            if ver_code:
                logging.debug("Manifest exists in subdir '{0}'. Found version {1} ({2})"
                              .format(subdir, version, ver_code))
                if int(ver_code) > int(h_code):
                    h_pak = package
                    h_code = str(int(ver_code))
                    h_ver = version

        if not h_pak:
            return None, "Couldn't find package ID"
        if h_ver:
            return h_ver, h_code
        return None, "Couldn't find any version information"

    except VCSException as vcse:
        msg = "VCS error while scanning app {0}: {1}".format(app.id, vcse)
        return None, msg
    except Exception:
        msg = "Could not scan app {0} due to unknown error: {1}".format(app.id, traceback.format_exc())
        return None, msg


def check_repo_trunk(app):
    try:
        if app.RepoType == 'srclib':
            build_dir = os.path.join('build', 'srclib', app.Repo)
            repo_type = common.get_srclib_vcs(app.Repo)
        else:
            build_dir = os.path.join('build', app.id)
            repo_type = app.RepoType

        if repo_type not in ('git-svn',):
            return None, 'RepoTrunk update mode only makes sense in git-svn repositories'

        # Set up vcs interface and make sure we have the latest code...
        vcs = common.get_vcs(app.RepoType, app.Repo, build_dir)

        vcs.go_to_revision(None)

        ref = vcs.get_ref()
        return ref, ref
    except VCSException as vcse:
        msg = "VCS error while scanning app {0}: {1}".format(app.id, vcse)
        return None, msg
    except Exception:
        msg = "Could not scan app {0} due to unknown error: {1}".format(app.id, traceback.format_exc())
        return None, msg


def check_g_play(app):
    """
    Check for a new version by looking at the Google Play Store.
    Returns (None, "a message") if this didn't work, or (version, None) for
    the details of the current version.
    """
    time.sleep(15)
    url = 'https://play.google.com/store/apps/details?id=' + app.id
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux i686; rv:18.0) Gecko/20100101 Firefox/18.0'}
    req = urllib.request.Request(url, None, headers)
    try:
        resp = urllib.request.urlopen(req, None, 20)  # nosec B310 URL base is hardcoded above
        page = resp.read().decode()
    except urllib.error.HTTPError as e:
        return None, str(e.code)
    except Exception as e:
        return None, 'Failed:' + str(e)

    version = None

    m = re.search('itemprop="softwareVersion">[ ]*([^<]+)[ ]*</div>', page)
    if m:
        version = html.unescape(m.group(1))

    if version == 'Varies with device':
        return None, 'Device-variable version, cannot use this method'

    if not version:
        return None, "Couldn't find version"
    return version.strip(), None


def try_init_submodules(app, last_build, vcs):
    """
    Try to init submodules if the last build entry used them.
    They might have been removed from the app's repo in the meantime,
    so if we can't find any submodules we continue with the updates check.
    If there is any other error in initializing them then we stop the check.
    """
    if last_build.submodules:
        try:
            vcs.init_submodules()
        except NoSubmodulesException:
            logging.info("No submodules present for {}".format(_get_app_name(app)))


def dirs_with_manifest(start_dir):
    """
    Return all directories under start_dir that contain any of the manifest
    files, and thus are probably an Android project.
    """
    for root, dirs, files in os.walk(start_dir):
        if any(m in files for m in [
               'AndroidManifest.xml', 'pom.xml', 'build.gradle', 'build.gradle.kts']):
            yield root


def possible_subdirs(app):
    """
    Tries to find a new subdir starting from the root build_dir. Returns said
    subdir relative to the build dir if found, None otherwise.
    """
    if app.RepoType == 'srclib':
        build_dir = os.path.join('build', 'srclib', app.Repo)
    else:
        build_dir = os.path.join('build', app.id)

    last_build = app.get_last_build()

    for d in dirs_with_manifest(build_dir):
        m_paths = common.manifest_paths(d, last_build.gradle)
        package = common.parse_android_manifests(m_paths, app)[2]
        if package is not None:
            subdir = os.path.relpath(d, build_dir)
            logging.debug("Adding possible subdir %s" % subdir)
            yield subdir


def _get_app_name(app):
    return common.get_app_display_name(app)


def _get_cv_name(app):
    return '%s (%s)' % (app.CurrentVersion, app.CurrentVersionCode)


def fetch_autoname(app, tag):
    if not app.RepoType or app.UpdateCheckMode in ('None', 'Static') or app.UpdateCheckName == "Ignore":
        return None

    if app.RepoType == 'srclib':
        build_dir = os.path.join('build', 'srclib', app.Repo)
    else:
        build_dir = os.path.join('build', app.id)

    try:
        vcs = common.get_vcs(app.RepoType, app.Repo, build_dir)
        vcs.go_to_revision(tag)
    except VCSException:
        return None

    last_build = app.get_last_build()

    logging.debug("...fetch auto name from " + build_dir)
    new_name = None
    for subdir in possible_subdirs(app):
        if subdir == '.':
            root_dir = build_dir
        else:
            root_dir = os.path.join(build_dir, subdir)
        new_name = common.fetch_real_name(root_dir, last_build.gradle)
        if new_name is not None:
            break
    commit_msg = None
    if new_name:
        logging.debug("...got autoname '" + new_name + "'")
        if new_name != app.AutoName:
            app.AutoName = new_name
            if not commit_msg:
                commit_msg = "Set autoname of {0}".format(_get_app_name(app))
    else:
        logging.debug("...couldn't get autoname")

    return commit_msg


def checkupdates_app(app):
    """
    If a change is made, commit_msg should be set to a description of it.
    Only if this is set will changes be written back to the metadata.
    """
    tag = None
    ver_code = None
    no_ver_ok = False
    mode = app.UpdateCheckMode
    if mode.startswith('Tags'):
        pattern = mode[5:] if len(mode) > 4 else None
        (version, ver_code, tag) = check_tags(app, pattern)
        if version == 'Unknown':
            version = tag
        msg = ver_code
    elif mode == 'RepoManifest':
        (version, ver_code) = check_repo_manifest(app)
        msg = ver_code
    elif mode.startswith('RepoManifest/'):
        tag = mode[13:]
        (version, ver_code) = check_repo_manifest(app, tag)
        msg = ver_code
    elif mode == 'RepoTrunk':
        (version, ver_code) = check_repo_trunk(app)
        msg = ver_code
    elif mode == 'HTTP':
        (version, ver_code) = check_http(app)
        msg = ver_code
    elif mode in ('None', 'Static'):
        version = None
        msg = 'Checking disabled'
        no_ver_ok = True
    else:
        version = None
        msg = 'Invalid update check method'

    if version and ver_code and app.VercodeOperation:
        if not common.VERCODE_OPERATION_RE.match(app.VercodeOperation):
            raise MetaDataException(_('Invalid VercodeOperation: {field}')
                                    .format(field=app.VercodeOperation))
        old_ver_code = str(int(ver_code))
        op = app.VercodeOperation.replace("%c", old_ver_code)
        ver_code = str(common.calculate_math_string(op))
        logging.debug("Applied vercode operation: %s -> %s" % (old_ver_code, ver_code))

    if version and any(version.startswith(s) for s in [
        '${',  # Gradle variable names
        '@string/',  # Strings we could not resolve
    ]):
        version = "Unknown"

    updating = False
    if version is None:
        log_msg = "...{0} : {1}".format(app.id, msg)
        if no_ver_ok:
            logging.info(log_msg)
        else:
            logging.warning(log_msg)
    elif ver_code == app.CurrentVersionCode:
        logging.info("...up to date")
    else:
        logging.debug("...updating - old vercode={0}, new vercode={1}".format(
            app.CurrentVersionCode, ver_code))
        app.CurrentVersion = version
        app.CurrentVersionCode = str(int(ver_code))
        updating = True

    commit_msg = fetch_autoname(app, tag)

    if updating:
        name = _get_app_name(app)
        ver = _get_cv_name(app)
        logging.info('...updating to version %s' % ver)
        commit_msg = 'Update CurrentVersion of %s to %s' % (name, ver)

    if options.auto:
        mode = app.AutoUpdateMode
        if not app.CurrentVersionCode:
            logging.warning("Can't auto-update app with no CurrentVersionCode: " + app.id)
        elif mode in ('None', 'Static'):
            pass
        elif mode.startswith('Version '):
            pattern = mode[8:]
            suffix = ''
            if pattern.startswith('+'):
                try:
                    suffix, pattern = pattern[1:].split(' ', 1)
                except ValueError:
                    raise MetaDataException("Invalid AutoUpdateMode: " + mode)

            got_cur = False
            latest = None
            for build in app.get('Builds', []):
                if int(build.versionCode) >= int(app.CurrentVersionCode):
                    got_cur = True
                if not latest or int(build.versionCode) > int(latest.versionCode):
                    latest = build

            if int(latest.versionCode) > int(app.CurrentVersionCode):
                logging.info("Refusing to auto update, since the latest build is newer")

            if not got_cur:
                new_build = copy.deepcopy(latest)
                new_build.disable = False
                new_build.versionCode = app.CurrentVersionCode
                new_build.versionName = app.CurrentVersion + suffix.replace('%c', new_build.versionCode)
                logging.info("...auto-generating build for " + new_build.versionName)
                if tag:
                    new_build.commit = tag
                else:
                    commit = pattern.replace('%v', app.CurrentVersion)
                    commit = commit.replace('%c', new_build.versionCode)
                    new_build.commit = commit

                app['Builds'].append(new_build)
                name = _get_app_name(app)
                ver = _get_cv_name(app)
                commit_msg = "Update %s to %s" % (name, ver)
        else:
            logging.warning('Invalid auto update mode "' + mode + '" on ' + app.id)

    if commit_msg:
        metadata.write_metadata(app.metadatapath, app)
        if options.commit:
            logging.info("Commiting update for " + app.metadatapath)
            gitcmd = ["git", "commit", "-m", commit_msg]
            if 'auto_author' in config:
                gitcmd.extend(['--author', config['auto_author']])
            gitcmd.extend(["--", app.metadatapath])
            if subprocess.call(gitcmd) != 0:
                raise FDroidException("Git commit failed")


def status_update_json(processed, failed):
    """Output a JSON file with metadata about this run."""

    logging.debug(_('Outputting JSON'))
    output = common.setup_status_output(start_timestamp)
    if processed:
        output['processed'] = processed
    if failed:
        output['failed'] = failed
    common.write_status_json(output)


def update_wiki(g_play_log, local_log):
    if config.get('wiki_server') and config.get('wiki_path'):
        try:
            import mwclient
            site = mwclient.Site((config['wiki_protocol'], config['wiki_server']),
                                 path=config['wiki_path'])
            site.login(config['wiki_user'], config['wiki_password'])

            # Write a page with the last build log for this version code
            wiki_page_path = 'checkupdates_' + time.strftime('%s', start_timestamp)
            new_page = site.Pages[wiki_page_path]
            txt = ''
            txt += "* command line: <code>" + ' '.join(sys.argv) + "</code>\n"
            txt += common.get_git_describe_link()
            txt += "* started at " + common.get_wiki_timestamp(start_timestamp) + '\n'
            txt += "* completed at " + common.get_wiki_timestamp() + '\n'
            txt += "\n\n"
            txt += common.get_android_tools_version_log()
            txt += "\n\n"
            if g_play_log:
                txt += '== --gplay check ==\n\n'
                txt += g_play_log
            if local_log:
                txt += '== local source check ==\n\n'
                txt += local_log
            new_page.save(txt, summary='Run log')
            new_page = site.Pages['checkupdates']
            new_page.save('#REDIRECT [[' + wiki_page_path + ']]', summary='Update redirect')
        except Exception as e:
            logging.error(_('Error while attempting to publish log: %s') % e)


config = None
options = None
start_timestamp = time.gmtime()


def main():
    global config, options

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*', help=_("application ID of file to operate on"))
    parser.add_argument("--auto", action="store_true", default=False,
                        help=_("Process auto-updates"))
    parser.add_argument("--autoonly", action="store_true", default=False,
                        help=_("Only process apps with auto-updates"))
    parser.add_argument("--commit", action="store_true", default=False,
                        help=_("Commit changes"))
    parser.add_argument("--allow-dirty", action="store_true", default=False,
                        help=_("Run on git repo that has uncommitted changes"))
    parser.add_argument("--gplay", action="store_true", default=False,
                        help=_("Only print differences with the Play Store"))
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    config = common.read_config(options)

    if not options.allow_dirty:
        status = subprocess.check_output(['git', 'status', '--porcelain'])
        if status:
            logging.error(_('Build metadata git repo has uncommitted changes!'))
            sys.exit(1)

    # Get all apps...
    all_apps = metadata.read_metadata()

    apps = common.read_app_args(options.appid, all_apps, False)

    g_play_log = ''
    if options.gplay:
        for app_id, app in apps.items():
            g_play_log += '* ' + app_id + '\n'
            version, reason = check_g_play(app)
            if version is None:
                if reason == '404':
                    logging.info("{0} is not in the Play Store".format(_get_app_name(app)))
                else:
                    logging.info("{0} encountered a problem: {1}".format(_get_app_name(app), reason))
            if version is not None:
                stored = app.CurrentVersion
                if not stored:
                    logging.info("{0} has no Current Version but has version {1} on the Play Store"
                                 .format(_get_app_name(app), version))
                elif LooseVersion(stored) < LooseVersion(version):
                    logging.info("{0} has version {1} on the Play Store, which is bigger than {2}"
                                 .format(_get_app_name(app), version, stored))
                else:
                    if stored != version:
                        logging.info("{0} has version {1} on the Play Store, which differs from {2}"
                                     .format(_get_app_name(app), version, stored))
                    else:
                        logging.info("{0} has the same version {1} on the Play Store"
                                     .format(_get_app_name(app), version))
        update_wiki(g_play_log, None)
        return

    local_log = ''
    processed = []
    failed = dict()
    for app_id, app in apps.items():

        if options.autoonly and app.AutoUpdateMode in ('None', 'Static'):
            logging.debug(_("Nothing to do for {appid}.").format(appid=app_id))
            continue

        msg = _("Processing {appid}").format(appid=app_id)
        logging.info(msg)
        local_log += '* ' + msg + '\n'

        try:
            checkupdates_app(app)
            processed.append(app_id)
        except Exception as e:
            msg = _("...checkupdate failed for {appid} : {error}").format(appid=app_id, error=e)
            logging.error(msg)
            local_log += msg + '\n'
            failed[app_id] = str(e)

    update_wiki(None, local_log)
    status_update_json(processed, failed)
    logging.info(_("Finished"))


if __name__ == "__main__":
    main()
