#!/usr/bin/env python3
#
# build.py - part of the FDroid server tools
# Copyright (C) 2010-2014, Ciaran Gultnieks, ciaran@ciarang.com
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

import argparse
import glob
import logging
import os
import posixpath
import re
import resource
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
from configparser import ConfigParser
from gettext import ngettext

import requests

from . import _
from . import common
from . import metadata
from . import net
from . import scanner
from . import vmtools
from .common import fdroid_popen
from .exception import FDroidException, BuildException, VCSException

try:
    import paramiko
except ImportError:
    pass


# Note that 'force' here also implies test mode.
def build_server(app, build, vcs, build_dir, output_dir, log_dir, force):
    """Do a build on the builder vm.

    :param log_dir:
    :param app: app metadata dict
    :param build:
    :param vcs: version control system controller object
    :param build_dir: local source-code checkout of app
    :param output_dir: target folder for the build result
    :param force:
    """

    global buildserver_id

    try:
        paramiko
    except NameError as e:
        raise BuildException("Paramiko is required to use the buildserver") from e
    if options.verbose:
        logging.getLogger("paramiko").setLevel(logging.INFO)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARN)

    ssh_info = vmtools.get_clean_builder('builder')

    output = None
    try:
        if not buildserver_id:
            try:
                buildserver_id = subprocess.check_output(['vagrant', 'ssh', '-c',
                                                          'cat /home/vagrant/buildserverid'],
                                                         cwd='builder').strip().decode()
                logging.debug(_('Fetched buildserverid from VM: {buildserverid}')
                              .format(buildserverid=buildserver_id))
            except Exception as e:
                if type(buildserver_id) is not str or not re.match('^[0-9a-f]{40}$', buildserver_id):
                    logging.info(subprocess.check_output(['vagrant', 'status'], cwd="builder"))
                    raise FDroidException("Could not obtain buildserverid from buldserver VM. "
                                          "(stored inside the buildserver VM at '/home/vagrant/buildserverid') "
                                          "Please reset your buildserver, the setup VM is broken.") from e

        # Open SSH connection...
        logging.info("Connecting to virtual machine...")
        ssh_s = paramiko.SSHClient()
        ssh_s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_s.connect(ssh_info['hostname'], username=ssh_info['user'],
                      port=ssh_info['port'], timeout=300,
                      look_for_keys=False, key_filename=ssh_info['idfile'])

        home_dir = posixpath.join('/home', ssh_info['user'])

        # Get an SFTP connection...
        ftp = ssh_s.open_sftp()
        ftp.get_channel().settimeout(60)

        # Put all the necessary files in place...
        ftp.chdir(home_dir)

        # Helper to copy the contents of a directory to the server...
        def send_dir(path):
            logging.debug("rsyncing " + path + " to " + ftp.getcwd())
            # TODO this should move to `vagrant rsync` from >= v1.5
            try:
                subprocess.check_output(['rsync', '--recursive', '--perms', '--links', '--quiet', '--rsh='
                                         + 'ssh -o StrictHostKeyChecking=no'
                                         + ' -o UserKnownHostsFile=/dev/null'
                                         + ' -o LogLevel=FATAL'
                                         + ' -o IdentitiesOnly=yes'
                                         + ' -o PasswordAuthentication=no'
                                         + ' -p ' + str(ssh_info['port'])
                                         + ' -i ' + ssh_info['idfile'],
                                         path,
                                         ssh_info['user'] + "@" + ssh_info['hostname'] + ":" + ftp.getcwd()],
                                        stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                raise FDroidException(str(e), e.output.decode())

        logging.info("Preparing server for build...")
        server_path = os.path.abspath(os.path.dirname(__file__))
        ftp.mkdir('fdroidserver')
        ftp.chdir('fdroidserver')
        ftp.put(os.path.join(server_path, '..', 'fdroid'), 'fdroid')
        ftp.put(os.path.join(server_path, '..', 'gradlew-fdroid'), 'gradlew-fdroid')
        ftp.chmod('fdroid', 0o755)  # nosec B103 permissions are appropriate
        ftp.chmod('gradlew-fdroid', 0o755)  # nosec B103 permissions are appropriate
        send_dir(os.path.join(server_path))
        ftp.chdir(home_dir)

        ftp.put(os.path.join(server_path, '..', 'buildserver',
                             'config.buildserver.yml'), 'config.yml')
        ftp.chmod('config.yml', 0o600)

        # Copy over the ID (head commit hash) of the fdroidserver in use...
        with open(os.path.join(os.getcwd(), 'tmp', 'fdroidserverid'), 'wb') as fp:
            fp.write(subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                             cwd=server_path))
        ftp.put('tmp/fdroidserverid', 'fdroidserverid')

        # Copy the metadata - just the file for this app...
        ftp.mkdir('metadata')
        ftp.mkdir('srclibs')
        ftp.chdir('metadata')
        ftp.put(app.metadatapath, os.path.basename(app.metadatapath))

        # And patches if there are any...
        if os.path.exists(os.path.join('metadata', app.id)):
            send_dir(os.path.join('metadata', app.id))

        ftp.chdir(home_dir)
        # Create the build directory...
        ftp.mkdir('build')
        ftp.chdir('build')
        ftp.mkdir('extlib')
        ftp.mkdir('srclib')
        # Copy any extlibs that are required...
        if build.extlibs:
            ftp.chdir(posixpath.join(home_dir, 'build', 'extlib'))
            for lib in build.extlibs:
                lib = lib.strip()
                libsrc = os.path.join('build/extlib', lib)
                if not os.path.exists(libsrc):
                    raise BuildException("Missing extlib {0}".format(libsrc))
                lp = lib.split('/')
                for d in lp[:-1]:
                    if d not in ftp.listdir():
                        ftp.mkdir(d)
                    ftp.chdir(d)
                ftp.put(libsrc, lp[-1])
                for _ignored in lp[:-1]:
                    ftp.chdir('..')
        # Copy any srclibs that are required...
        srclib_paths = []
        if build.srclibs:
            for lib in build.srclibs:
                srclib_paths.append(
                    common.get_srclib(lib, 'build/srclib', base_path=True, prepare=False))

        # If one was used for the main source, add that too.
        base_srclib = vcs.get_srclib()
        if base_srclib:
            srclib_paths.append(base_srclib)
        for name, number, lib in srclib_paths:
            logging.info("Sending srclib '%s'" % lib)
            ftp.chdir(posixpath.join(home_dir, 'build', 'srclib'))
            if not os.path.exists(lib):
                raise BuildException("Missing srclib directory '" + lib + "'")
            fv = '.fdroidvcs-' + name
            ftp.put(os.path.join('build/srclib', fv), fv)
            send_dir(lib)
            # Copy the metadata file too...
            ftp.chdir(posixpath.join(home_dir, 'srclibs'))
            srclibs_file = os.path.join('srclibs', name + '.yml')
            if os.path.isfile(srclibs_file):
                ftp.put(srclibs_file, os.path.basename(srclibs_file))
            else:
                raise BuildException(_('cannot find required srclibs: "{path}"')
                                     .format(path=srclibs_file))
        # Copy the main app source code
        # (no need if it's a srclib)
        if (not base_srclib) and os.path.exists(build_dir):
            ftp.chdir(posixpath.join(home_dir, 'build'))
            fv = '.fdroidvcs-' + app.id
            ftp.put(os.path.join('build', fv), fv)
            send_dir(build_dir)

        # Execute the build script...
        logging.info("Starting build...")
        channel = ssh_s.get_transport().open_session()
        channel.get_pty()
        cmdline = posixpath.join(home_dir, 'fdroidserver', 'fdroid')
        cmdline += ' build --on-server'
        if force:
            cmdline += ' --force --test'
        if options.verbose:
            cmdline += ' --verbose'
        if options.skipscan:
            cmdline += ' --skip-scan'
        if options.notarball:
            cmdline += ' --no-tarball'
        cmdline += " %s:%s" % (app.id, build.versionCode)
        channel.exec_command('bash --login -c "' + cmdline + '"')  # nosec B601 inputs are sanitized

        # Fetch build process output ...
        try:
            cmd_stdout = channel.makefile('rb', 1024)
            output = bytes()
            output += common.get_android_tools_version_log(build.ndk_path()).encode()
            while not channel.exit_status_ready():
                line = cmd_stdout.readline()
                if line:
                    if options.verbose:
                        logging.debug("buildserver > " + str(line, 'utf-8').rstrip())
                    output += line
                else:
                    time.sleep(0.05)
            for line in cmd_stdout.readlines():
                if options.verbose:
                    logging.debug("buildserver > " + str(line, 'utf-8').rstrip())
                output += line
        finally:
            cmd_stdout.close()

        # Check build process exit status ...
        logging.info("...getting exit status")
        return_code = channel.recv_exit_status()
        if return_code != 0:
            if timeout_event.is_set():
                message = "Timeout exceeded! Build VM force-stopped for {0}:{1}"
            else:
                message = "Build.py failed on server for {0}:{1}"
            raise BuildException(message.format(app.id, build.versionName),
                                 None if options.verbose else str(output, 'utf-8'))

        # Retrieve logs...
        tools_version_log = common.get_tools_version_log_name(app, build)
        try:
            ftp.chdir(posixpath.join(home_dir, log_dir))
            ftp.get(tools_version_log, os.path.join(log_dir, tools_version_log))
            logging.debug('retrieved %s', tools_version_log)
        except Exception as e:
            logging.warning('could not get %s from builder vm: %s' % (tools_version_log, e))

        # Retrieve the built files...
        logging.info("Retrieving build output...")
        if force:
            ftp.chdir(posixpath.join(home_dir, 'tmp'))
        else:
            ftp.chdir(posixpath.join(home_dir, 'unsigned'))
        apk_file = common.get_release_filename(app, build)
        tarball = common.get_src_name(app, build)
        try:
            ftp.get(apk_file, os.path.join(output_dir, apk_file))
            if not options.notarball:
                ftp.get(tarball, os.path.join(output_dir, tarball))
        except Exception:
            raise BuildException(
                "Build failed for {0}:{1} - missing output files".format(
                    app.id, build.versionName), None if options.verbose else str(output, 'utf-8'))
        ftp.close()

    finally:
        # Suspend the build server.
        vm = vmtools.get_build_vm('builder')
        logging.info('destroying buildserver after build')
        vm.destroy()

        # deploy logfile to repository web server
        if output:
            common.deploy_build_log_with_rsync(app.id, build.versionCode, output)
        else:
            logging.debug('skip publishing full build logs: '
                          'no output present')


def force_gradle_build_tools(build_dir, build_tools):
    for root, dirs, files in os.walk(build_dir):
        for filename in files:
            if not filename.endswith('.gradle'):
                continue
            path = os.path.join(root, filename)
            if not os.path.isfile(path):
                continue
            logging.debug("Forcing build-tools %s in %s" % (build_tools, path))
            common.reg_sub_file(r"""(\s*)buildToolsVersion([\s=]+).*""",
                                r"""\1buildToolsVersion\2'%s'""" % build_tools,
                                path)


def transform_first_char(string, method):
    """Uses method() on the first character of string."""
    if len(string) == 0:
        return string
    if len(string) == 1:
        return method(string)
    return method(string[0]) + string[1:]


def add_failed_builds_entry(failed_builds, app_id, build, entry):
    failed_builds.append([app_id, int(build.versionCode), str(entry)])


def get_metadata_from_apk(app, build, apk_file):
    """Get the required metadata from the built APK

    version_name is allowed to be a blank string, i.e.
    """

    app_id, version_code, version_name = common.get_apk_id(apk_file)
    native_code = common.get_native_code(apk_file)

    if build.buildjni and build.buildjni != ['no'] and not native_code:
        raise BuildException("Native code should have been built but none was packaged")
    if build.novcheck:
        version_code = build.versionCode
        version_name = build.versionName
    if not version_code or version_name is None:
        raise BuildException("Could not find version information in build in output")
    if not app_id:
        raise BuildException("Could not find package ID in output")
    if app_id != app.id:
        raise BuildException("Wrong package ID - build " + app_id + " but expected " + app.id)

    return version_code, version_name


def build_local(app, build, vcs, build_dir, output_dir, log_dir, srclib_dir, extlib_dir, tmp_dir, force, on_server,
                refresh):
    """Do a build locally."""
    ndk_path = build.ndk_path()
    if build.ndk or (build.buildjni and build.buildjni != ['no']):
        if not ndk_path:
            logging.critical("Android NDK version '%s' could not be found!" % build.ndk or 'r12b')
            logging.critical("Configured versions:")
            for k, v in config['ndk_paths'].items():
                if k.endswith("_orig"):
                    continue
                logging.critical("  %s: %s" % (k, v))
            raise FDroidException()
        elif not os.path.isdir(ndk_path):
            logging.critical("Android NDK '%s' is not a directory!" % ndk_path)
            raise FDroidException()

    common.set_fdroid_popen_env(build)

    # create ..._toolsversion.log when running in builder vm
    if on_server:
        # before doing anything, run the sudo commands to setup the VM
        if build.sudo:
            logging.info("Running 'sudo' commands in %s" % os.getcwd())

            p = fdroid_popen(['sudo', 'DEBIAN_FRONTEND=noninteractive',
                              'bash', '-x', '-c', build.sudo])
            if p.returncode != 0:
                raise BuildException("Error running sudo command for %s:%s" %
                                     (app.id, build.versionName), p.output)

        p = fdroid_popen(['sudo', 'passwd', '--lock', 'root'])
        if p.returncode != 0:
            raise BuildException("Error locking root account for %s:%s" %
                                 (app.id, build.versionName), p.output)

        p = fdroid_popen(['sudo', 'SUDO_FORCE_REMOVE=yes', 'dpkg', '--purge', 'sudo'])
        if p.returncode != 0:
            raise BuildException("Error removing sudo for %s:%s" %
                                 (app.id, build.versionName), p.output)

        log_path = os.path.join(log_dir,
                                common.get_tools_version_log_name(app, build))
        with open(log_path, 'w') as f:
            f.write(common.get_android_tools_version_log(build.ndk_path()))
    else:
        if build.sudo:
            logging.warning(
                '%s:%s runs this on the buildserver with sudo:\n\t%s\nThese commands were skipped because fdroid '
                'build is not running on a dedicated build server. '
                % (app.id, build.versionName, build.sudo))

    # Prepare the source code...
    root_dir, srclib_paths = common.prepare_source(vcs, app, build,
                                                   build_dir, srclib_dir,
                                                   extlib_dir, on_server, refresh)

    # We need to clean via the build tool in case the binary dirs are
    # different from the default ones
    p = None
    gradle_tasks = []
    b_method = build.build_method()
    if b_method == 'maven':
        logging.info("Cleaning Maven project...")
        cmd = [config['mvn3'], 'clean', '-Dandroid.sdk.path=' + config['sdk_path']]

        if '@' in build.maven:
            maven_dir = os.path.join(root_dir, build.maven.split('@', 1)[1])
            maven_dir = os.path.normpath(maven_dir)
        else:
            maven_dir = root_dir

        p = fdroid_popen(cmd, cwd=maven_dir)

    elif b_method == 'gradle':

        logging.info("Cleaning Gradle project...")

        if build.preassemble:
            gradle_tasks += build.preassemble

        flavours = build.gradle
        if flavours == ['yes']:
            flavours = []

        flavours_cmd = ''.join([transform_first_char(flav, str.upper) for flav in flavours])

        gradle_tasks += ['assemble' + flavours_cmd + 'Release']

        cmd = [config['gradle']]
        if build.gradleprops:
            cmd += ['-P' + kv for kv in build.gradleprops]

        cmd += ['clean']
        p = fdroid_popen(cmd, cwd=root_dir,
                         envs={"GRADLE_VERSION_DIR": config['gradle_version_dir'], "CACHEDIR": config['cachedir']})

    elif b_method == 'buildozer':
        pass

    elif b_method == 'ant':
        logging.info("Cleaning Ant project...")
        p = fdroid_popen(['ant', 'clean'], cwd=root_dir)

    if p is not None and p.returncode != 0:
        raise BuildException("Error cleaning %s:%s" %
                             (app.id, build.versionName), p.output)

    for root, dirs, files in os.walk(build_dir):

        def del_dirs(dl):
            for d in dl:
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)

        def del_files(fl):
            for f in fl:
                if f in files:
                    os.remove(os.path.join(root, f))

        if any(f in files for f in ['build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts']):
            # Even when running clean, gradle stores task/artifact caches in
            # .gradle/ as binary files. To avoid overcomplicating the scanner,
            # manually delete them, just like `gradle clean` should have removed
            # the build/* dirs.
            del_dirs([os.path.join('build', 'android-profile'),
                      os.path.join('build', 'generated'),
                      os.path.join('build', 'intermediates'),
                      os.path.join('build', 'outputs'),
                      os.path.join('build', 'reports'),
                      os.path.join('build', 'tmp'),
                      os.path.join('buildSrc', 'build'),
                      '.gradle'])
            del_files(['gradlew', 'gradlew.bat'])

        if 'pom.xml' in files:
            del_dirs(['target'])

        if any(f in files for f in ['ant.properties', 'project.properties', 'build.xml']):
            del_dirs(['bin', 'gen'])

        if 'jni' in dirs:
            del_dirs(['obj'])

    if options.skipscan:
        if build.scandelete:
            raise BuildException("Refusing to skip source scan since scandelete is present")
    else:
        # Scan before building...
        logging.info("Scanning source for common problems...")
        scanner.options = options  # pass verbose through
        count = scanner.scan_source(build_dir, build)
        if count > 0:
            if force:
                logging.warning(ngettext('Scanner found {} problem',
                                         'Scanner found {} problems', count).format(count))
            else:
                raise BuildException(ngettext(
                    "Can't build due to {} error while scanning",
                    "Can't build due to {} errors while scanning", count).format(count))

    if not options.notarball:
        # Build the source tarball right before we build the release...
        logging.info("Creating source tarball...")
        tar_name = common.get_src_name(app, build)
        tarball = tarfile.open(os.path.join(tmp_dir, tar_name), "w:gz")

        def tar_exc(t):
            return None if any(t.name.endswith(s) for s in ['.svn', '.git', '.hg', '.bzr']) else t

        tarball.add(build_dir, tar_name, filter=tar_exc)
        tarball.close()

    # Run a build command if one is required...
    if build.build:
        logging.info("Running 'build' commands in %s" % root_dir)
        cmd = common.replace_config_vars(build.build, build)

        # Substitute source library paths into commands...
        for name, number, libpath in srclib_paths:
            cmd = cmd.replace('$$' + name + '$$', os.path.join(os.getcwd(), libpath))

        p = fdroid_popen(['bash', '-x', '-c', cmd], cwd=root_dir)

        if p.returncode != 0:
            raise BuildException("Error running build command for %s:%s" %
                                 (app.id, build.versionName), p.output)

    # Build native stuff if required...
    if build.buildjni and build.buildjni != ['no']:
        logging.info("Building the native code")
        jni_components = build.buildjni

        if jni_components == ['yes']:
            jni_components = ['']
        cmd = [os.path.join(ndk_path, "ndk-build"), "-j1"]
        for d in jni_components:
            if d:
                logging.info("Building native code in '%s'" % d)
            else:
                logging.info("Building native code in the main project")
            manifest = os.path.join(root_dir, d, 'AndroidManifest.xml')
            if os.path.exists(manifest):
                # Read and write the whole AM.xml to fix newlines and avoid
                # the ndk r8c or later 'wordlist' errors. The outcome of this
                # under gnu/linux is the same as when using tools like
                # dos2unix, but the native python way is faster and will
                # work in non-unix systems.
                manifest_text = open(manifest, 'U').read()
                open(manifest, 'w').write(manifest_text)
                # In case the AM.xml read was big, free the memory
                del manifest_text
            p = fdroid_popen(cmd, cwd=os.path.join(root_dir, d))
            if p.returncode != 0:
                raise BuildException("NDK build failed for %s:%s" % (app.id, build.versionName), p.output)

    p = None

    # Build the release...
    if b_method == 'maven':
        logging.info("Building Maven project...")

        if '@' in build.maven:
            maven_dir = os.path.join(root_dir, build.maven.split('@', 1)[1])
        else:
            maven_dir = root_dir

        mvncmd = [config['mvn3'], '-Dandroid.sdk.path=' + config['sdk_path'],
                  '-Dmaven.jar.sign.skip=true', '-Dmaven.test.skip=true',
                  '-Dandroid.sign.debug=false', '-Dandroid.release=true',
                  'package']
        if build.target:
            target = build.target.split('-')[1]
            common.reg_sub_file(r'<platform>[0-9]*</platform>',
                                r'<platform>%s</platform>' % target,
                                os.path.join(root_dir, 'pom.xml'))
            if '@' in build.maven:
                common.reg_sub_file(r'<platform>[0-9]*</platform>',
                                    r'<platform>%s</platform>' % target,
                                    os.path.join(maven_dir, 'pom.xml'))

        p = fdroid_popen(mvncmd, cwd=maven_dir)

        bin_dir = os.path.join(root_dir, 'target')

    elif b_method == 'buildozer':
        logging.info("Building Kivy project using buildozer...")

        # parse buildozer.spez
        spec = os.path.join(root_dir, 'buildozer.spec')
        if not os.path.exists(spec):
            raise BuildException("Expected to find buildozer-compatible spec at {0}"
                                 .format(spec))
        defaults = {'orientation': 'landscape', 'icon': '',
                    'permissions': '', 'android.api': "19"}
        b_config = ConfigParser(defaults, allow_no_value=True)
        b_config.read(spec)

        # update spec with sdk and ndk locations to prevent buildozer from
        # downloading.
        loc_ndk = common.env['ANDROID_NDK']
        loc_sdk = common.env['ANDROID_SDK']
        if loc_ndk == '$ANDROID_NDK':
            loc_ndk = loc_sdk + '/ndk-bundle'

        bc_ndk = None
        bc_sdk = None
        try:
            bc_ndk = b_config.get('app', 'android.sdk_path')
        except Exception:
            pass
        try:
            bc_sdk = b_config.get('app', 'android.ndk_path')
        except Exception:
            pass

        if bc_sdk is None:
            b_config.set('app', 'android.sdk_path', loc_sdk)
        if bc_ndk is None:
            b_config.set('app', 'android.ndk_path', loc_ndk)

        f_spec = open(spec, 'w')
        b_config.write(f_spec)
        f_spec.close()

        logging.info("sdk_path = %s" % loc_sdk)
        logging.info("ndk_path = %s" % loc_ndk)

        p = None
        # execute buildozer
        cmd = ['buildozer', 'android', 'release']
        try:
            p = fdroid_popen(cmd, cwd=root_dir)
        except Exception:
            pass

        # buildozer not installed ? clone repo and run
        if p is None or p.returncode != 0:
            cmd = ['git', 'clone', 'https://github.com/kivy/buildozer.git']
            p = subprocess.Popen(cmd, cwd=root_dir, shell=False)
            p.wait()
            if p.returncode != 0:
                raise BuildException("Distribute build failed")

            cmd = ['python', 'buildozer/buildozer/scripts/client.py', 'android', 'release']
            p = fdroid_popen(cmd, cwd=root_dir)

        # expected to fail.
        # Signing will fail if not set by environment vars (cf. p4a docs).
        # But the unsigned APK will be ok.
        p.returncode = 0

    elif b_method == 'gradle':
        logging.info("Building Gradle project...")

        cmd = [config['gradle']]
        if build.gradleprops:
            cmd += ['-P' + kv for kv in build.gradleprops]

        cmd += gradle_tasks

        p = fdroid_popen(cmd, cwd=root_dir,
                         envs={"GRADLE_VERSION_DIR": config['gradle_version_dir'], "CACHEDIR": config['cachedir']})

    elif b_method == 'ant':
        logging.info("Building Ant project...")
        cmd = ['ant']
        if build.antcommands:
            cmd += build.antcommands
        else:
            cmd += ['release']
        p = fdroid_popen(cmd, cwd=root_dir)

        bin_dir = os.path.join(root_dir, 'bin')

    if os.path.isdir(os.path.join(build_dir, '.git')):
        import git
        commit_id = common.get_head_commit_id(git.repo.Repo(build_dir))
    else:
        commit_id = build.commit

    if p is not None and p.returncode != 0:
        raise BuildException("Build failed for %s:%s@%s" % (app.id, build.versionName, commit_id),
                             p.output)
    logging.info("Successfully built version {versionName} of {appid} from {commit_id}"
                 .format(versionName=build.versionName, appid=app.id, commit_id=commit_id))

    o_method = build.output_method()
    if o_method == 'maven':
        stdout_apk = '\n'.join([
            line for line in p.output.splitlines() if any(
                a in line for a in ('.apk', '.ap_', '.jar'))])
        m = re.match(r".*^\[INFO\] .*apkbuilder.*/([^/]*)\.apk",
                     stdout_apk, re.S | re.M)
        if not m:
            m = re.match(r".*^\[INFO] Creating additional unsigned apk file .*/([^/]+)\.apk[^l]",
                         stdout_apk, re.S | re.M)
        if not m:
            m = re.match(r'.*^\[INFO] [^$]*aapt \[package,[^$]*' + bin_dir + r'/([^/]+)\.ap[_k][,\]]',
                         stdout_apk, re.S | re.M)

        if not m:
            m = re.match(r".*^\[INFO] Building jar: .*/" + bin_dir + r"/(.+)\.jar",
                         stdout_apk, re.S | re.M)
        if not m:
            raise BuildException('Failed to find output')
        src = m.group(1)
        src = os.path.join(bin_dir, src) + '.apk'

    elif o_method == 'buildozer':
        src = None
        for apks_dir in [
            os.path.join(root_dir, '.buildozer', 'android', 'platform', 'build', 'dists', b_config.get('app', 'title'),
                         'bin'),
        ]:
            for apk_glob in ['*-release-unsigned.apk', '*-unsigned.apk', '*.apk']:
                apks = glob.glob(os.path.join(apks_dir, apk_glob))

                if len(apks) > 1:
                    raise BuildException('More than one resulting apks found in %s' % apks_dir,
                                         '\n'.join(apks))
                if len(apks) == 1:
                    src = apks[0]
                    break
            if src is not None:
                break

        if src is None:
            raise BuildException('Failed to find any output apks')

    elif o_method == 'gradle':
        src = None
        apk_dirs = [
            # gradle plugin >= 3.0
            os.path.join(root_dir, 'build', 'outputs', 'apk', 'release'),
            # gradle plugin < 3.0 and >= 0.11
            os.path.join(root_dir, 'build', 'outputs', 'apk'),
            # really old path
            os.path.join(root_dir, 'build', 'apk'),
        ]
        # If we build with gradle flavours with gradle plugin >= 3.0 the APK will be in
        # a subdirectory corresponding to the flavour command used, but with different
        # capitalization.
        if flavours_cmd:
            apk_dirs.append(
                os.path.join(root_dir, 'build', 'outputs', 'apk', transform_first_char(flavours_cmd, str.lower),
                             'release'))
        for apks_dir in apk_dirs:
            for apk_glob in ['*-release-unsigned.apk', '*-unsigned.apk', '*.apk']:
                apks = glob.glob(os.path.join(apks_dir, apk_glob))

                if len(apks) > 1:
                    raise BuildException('More than one resulting apks found in %s' % apks_dir,
                                         '\n'.join(apks))
                if len(apks) == 1:
                    src = apks[0]
                    break
            if src is not None:
                break

        if src is None:
            raise BuildException('Failed to find any output apks')

    elif o_method == 'ant':
        stdout_apk = '\n'.join([
            line for line in p.output.splitlines() if '.apk' in line])
        src = re.match(r".*^.*Creating (.+) for release.*$.*", stdout_apk,
                       re.S | re.M).group(1)
        src = os.path.join(bin_dir, src)
    elif o_method == 'raw':
        output_path = common.replace_build_vars(build.output, build)
        globpath = os.path.join(root_dir, output_path)
        apks = glob.glob(globpath)
        if len(apks) > 1:
            raise BuildException('Multiple apks match %s' % globpath, '\n'.join(apks))
        if len(apks) < 1:
            raise BuildException('No apks match %s' % globpath)
        src = os.path.normpath(apks[0])

    # Make sure it's not debuggable...
    if common.is_apk_and_debuggable(src):
        raise BuildException("APK is debuggable")

    # By way of a sanity check, make sure the version and version
    # code in our new APK match what we expect...
    logging.debug("Checking " + src)
    if not os.path.exists(src):
        raise BuildException("Unsigned APK is not at expected location of " + src)

    if common.get_file_extension(src) == 'apk':
        ver_code, version = get_metadata_from_apk(app, build, src)
        if version != build.versionName or ver_code != build.versionCode:
            raise BuildException(("Unexpected version/version code in output;"
                                  " APK: '%s' / '%s', "
                                  " Expected: '%s' / '%s'")
                                 % (version, str(ver_code), build.versionName,
                                    str(build.versionCode)))
        if (options.scan_binary or config.get('scan_binary')) and not options.skipscan:
            if scanner.scan_binary(src):
                raise BuildException("Found blacklisted packages in final apk!")

    # Copy the unsigned APK to our destination directory for further
    # processing (by publish.py)...
    destination = os.path.join(output_dir, common.get_release_filename(app, build))
    shutil.copyfile(src, destination)

    # Move the source tarball into the output directory...
    if output_dir != tmp_dir and not options.notarball:
        shutil.move(os.path.join(tmp_dir, tar_name),
                    os.path.join(output_dir, tar_name))


def try_build(app, build, build_dir, output_dir, log_dir, also_check_dir, srclib_dir, extlib_dir, tmp_dir, repo_dir,
              vcs, test, server, force, on_server, refresh):
    """
    Build a particular version of an application, if it needs building.

    :param app:
    :param build:
    :param build_dir:
    :param output_dir: The directory where the build output will go. Usually
       this is the 'unsigned' directory.
    :param log_dir:
    :param also_check_dir: An additional location for checking if the build
       is necessary (usually the archive repo).
    :param srclib_dir:
    :param extlib_dir:
    :param tmp_dir:
    :param repo_dir: The repo directory - used for checking if the build is
       necessary.
    :param vcs:
    :param test: True if building in test mode, in which case the build will
       always happen, even if the output already exists. In test mode, the
       output directory should be a temporary location, not any of the real
       ones.
    :param server:
    :param force:
    :param on_server:
    :param refresh:
    :return: True if the build was done, False if it wasn't necessary.
    """
    destination_file = common.get_release_filename(app, build)

    destination = os.path.join(output_dir, destination_file)
    destination_repo = os.path.join(repo_dir, destination_file)

    if not test:
        if os.path.exists(destination) or os.path.exists(destination_repo):
            return False

        if also_check_dir:
            destination_also = os.path.join(also_check_dir, destination_file)
            if os.path.exists(destination_also):
                return False

    if build.disable and not options.force:
        return False

    logging.info("Building version %s (%s) of %s" % (
        build.versionName, build.versionCode, app.id))

    if server:
        # When using server mode, still keep a local cache of the repo, by
        # grabbing the source now.
        vcs.go_to_revision(build.commit, refresh)

        build_server(app, build, vcs, build_dir, output_dir, log_dir, force)
    else:
        build_local(app, build, vcs, build_dir, output_dir, log_dir, srclib_dir, extlib_dir, tmp_dir, force, on_server,
                    refresh)
    return True


def force_halt_build(timeout):
    """Halt the currently running Vagrant VM, to be called from a Timer"""
    logging.error(_('Force halting build after {0} sec timeout!').format(timeout))
    timeout_event.set()
    vm = vmtools.get_build_vm('builder')
    vm.halt()


def parse_commandline():
    """Parse the command line. Returns options, parser."""
    parser = argparse.ArgumentParser(usage="%(prog)s [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*',
                        help=_("application ID with optional versionCode in the form APPID[:VERCODE]"))
    parser.add_argument("-l", "--latest", action="store_true", default=False,
                        help=_("Build only the latest version of each package"))
    parser.add_argument("-s", "--stop", action="store_true", default=False,
                        help=_("Make the build stop on exceptions"))
    parser.add_argument("-t", "--test", action="store_true", default=False,
                        help=_(
                            "Test mode - put output in the tmp directory only, and always build, even if the output "
                            "already exists."))
    parser.add_argument("--server", action="store_true", default=False,
                        help=_("Use build server"))
    parser.add_argument("--reset-server", action="store_true", default=False,
                        help=_("Reset and create a brand new build server, even if the existing one appears to be ok."))
    # this option is internal API for telling fdroid that
    # it's running inside a buildserver vm.
    parser.add_argument("--on-server", dest="onserver", action="store_true", default=False,
                        help=argparse.SUPPRESS)
    parser.add_argument("--skip-scan", dest="skipscan", action="store_true", default=False,
                        help=_("Skip scanning the source code for binaries and other problems"))
    parser.add_argument("--scan-binary", action="store_true", default=False,
                        help=_("Scan the resulting APK(s) for known non-free classes."))
    parser.add_argument("--no-tarball", dest="notarball", action="store_true", default=False,
                        help=_("Don't create a source tarball, useful when testing a build"))
    parser.add_argument("--no-refresh", dest="refresh", action="store_false", default=True,
                        help=_("Don't refresh the repository, useful when testing a build with no internet connection"))
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help=_(
                            "Force build of disabled apps, and carries on regardless of scan problems. Only allowed "
                            "in test mode."))
    parser.add_argument("-a", "--all", action="store_true", default=False,
                        help=_("Build all applications available"))
    parser.add_argument("-w", "--wiki", default=False, action="store_true",
                        help=_("Update the wiki"))
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    # Force --stop with --on-server to get correct exit code
    if options.onserver:
        options.stop = True

    if options.force and not options.test:
        parser.error("option %s: Force is only allowed in test mode" % "force")

    return options, parser


options = None
config = None
buildserver_id = None
fdroidserver_id = None
start_timestamp = time.gmtime()
status_output = None
timeout_event = threading.Event()


def main():
    global options, config, buildserver_id, fdroidserver_id

    options, parser = parse_commandline()

    # The defaults for .fdroid.* metadata that is included in a git repo are
    # different than for the standard metadata/ layout because expectations
    # are different.  In this case, the most common user will be the app
    # developer working on the latest update of the app on their own machine.
    local_metadata_files = common.get_local_metadata_files()
    if len(local_metadata_files) == 1:  # there is local metadata in an app's source
        config = dict(common.default_config)
        # `fdroid build` should build only the latest version by default since
        # most of the time the user will be building the most recent update
        if not options.all:
            options.latest = True
    elif len(local_metadata_files) > 1:
        raise FDroidException("Only one local metadata file allowed! Found: "
                              + " ".join(local_metadata_files))
    else:
        if not os.path.isdir('metadata') and len(local_metadata_files) == 0:
            raise FDroidException("No app metadata found, nothing to process!")
        if not options.appid and not options.all:
            parser.error("option %s: If you really want to build all the apps, use --all" % "all")

    config = common.read_config(options)

    if config['build_server_always']:
        options.server = True
    if options.reset_server and not options.server:
        parser.error("option %s: Using --reset-server without --server makes no sense" % "reset-server")

    if options.onserver or not options.server:
        for d in ['build-tools', 'platform-tools', 'tools']:
            if not os.path.isdir(os.path.join(config['sdk_path'], d)):
                raise FDroidException(_("Android SDK '{path}' does not have '{dirname}' installed!")
                                      .format(path=config['sdk_path'], dirname=d))

    log_dir = 'logs'
    if not os.path.isdir(log_dir):
        logging.info("Creating log directory")
        os.makedirs(log_dir)

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        logging.info("Creating temporary directory")
        os.makedirs(tmp_dir)

    if options.test:
        output_dir = tmp_dir
    else:
        output_dir = 'unsigned'
        if not os.path.isdir(output_dir):
            logging.info("Creating output directory")
            os.makedirs(output_dir)
    binaries_dir = os.path.join(output_dir, 'binaries')

    if config['archive_older'] != 0:
        also_check_dir = 'archive'
    else:
        also_check_dir = None

    if options.onserver:
        status_output = dict()  # HACK dummy placeholder
    else:
        status_output = common.setup_status_output(start_timestamp)

    repo_dir = 'repo'

    build_dir = 'build'
    if not os.path.isdir(build_dir):
        logging.info("Creating build directory")
        os.makedirs(build_dir)
    srclib_dir = os.path.join(build_dir, 'srclib')
    extlib_dir = os.path.join(build_dir, 'extlib')

    # Read all app and srclib metadata
    packages = common.read_pkg_args(options.appid, True)
    all_apps = metadata.read_metadata(packages, sort_by_time=True)
    apps = common.read_app_args(options.appid, all_apps, True)

    for app_id, app in list(apps.items()):
        if (app.get('Disabled') and not options.force) or not app.get('RepoType') or not app.get('Builds', []):
            del apps[app_id]

    if not apps:
        raise FDroidException("No apps to process.")

    # make sure enough open files are allowed to process everything
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if len(apps) > soft:
        try:
            soft = len(apps) * 2
            if soft > hard:
                soft = hard
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
            logging.debug(_('Set open file limit to {integer}')
                          .format(integer=soft))
        except (OSError, ValueError) as e:
            logging.warning(_('Setting open file limit failed: ') + str(e))

    if options.latest:
        for app in apps.values():
            for build in reversed(app.get('Builds', [])):
                if build.disable and not options.force:
                    continue
                app['Builds'] = [build]
                break

    if options.wiki:
        import mwclient
        site = mwclient.Site((config['wiki_protocol'], config['wiki_server']),
                             path=config['wiki_path'])
        site.login(config['wiki_user'], config['wiki_password'])

    # Build applications...
    failed_builds = []
    build_succeeded = []
    build_succeeded_ids = []
    status_output['failedBuilds'] = failed_builds
    status_output['successfulBuilds'] = build_succeeded
    status_output['successfulBuildIds'] = build_succeeded_ids
    # Only build for 72 hours, then stop gracefully.
    end_time = time.time() + 72 * 60 * 60
    max_build_time_reached = False
    for app_id, app in apps.items():

        first = True

        for build in app.get('Builds', []):
            if time.time() > end_time:
                max_build_time_reached = True
                break

            # Enable watchdog timer (2 hours by default).
            if build.timeout is None:
                timeout = 7200
            else:
                timeout = int(build.timeout)
            if options.server and timeout > 0:
                logging.debug(_('Setting {0} sec timeout for this build').format(timeout))
                timer = threading.Timer(timeout, force_halt_build, [timeout])
                timeout_event.clear()
                timer.start()
            else:
                timer = None

            wiki_log = None
            build_start_time = common.get_wiki_timestamp()
            tools_version_log = ''
            if not options.onserver:
                tools_version_log = common.get_android_tools_version_log(build.ndk_path())
                common.write_running_status_json(status_output)
            try:
                # For the first build of a particular app, we need to set up
                # the source repo. We can reuse it on subsequent builds, if
                # there are any.
                if first:
                    vcs, build_dir = common.setup_vcs(app)
                    first = False

                logging.info("Using %s" % vcs.client_version())
                logging.debug("Checking " + build.versionName)
                if try_build(app, build, build_dir, output_dir, log_dir, also_check_dir, srclib_dir, extlib_dir,
                             tmp_dir, repo_dir, vcs, options.test, options.server, options.force, options.onserver,
                             options.refresh):
                    tools_log = os.path.join(log_dir,
                                             common.get_tools_version_log_name(app, build))
                    if not options.onserver and os.path.exists(tools_log):
                        with open(tools_log, 'r') as f:
                            tools_version_log = ''.join(f.readlines())
                        os.remove(tools_log)

                    if app.Binaries is not None:
                        # This is an app where we build from source, and
                        # verify the APK contents against a developer's
                        # binary. We get that binary now, and save it
                        # alongside our built one in the 'unsigned'
                        # directory.
                        if not os.path.isdir(binaries_dir):
                            os.makedirs(binaries_dir)
                            logging.info("Created directory for storing "
                                         "developer supplied reference "
                                         "binaries: '{path}'"
                                         .format(path=binaries_dir))
                        url = app.Binaries
                        url = url.replace('%v', build.versionName)
                        url = url.replace('%c', str(build.versionCode))
                        logging.info("...retrieving " + url)
                        of = re.sub(r'\.apk$', '.binary.apk', common.get_release_filename(app, build))
                        of = os.path.join(binaries_dir, of)
                        try:
                            net.download_file(url, local_filename=of)
                        except requests.exceptions.HTTPError as e:
                            raise FDroidException(
                                'Downloading Binaries from %s failed.' % url) from e

                        # Now we check whether the build can be verified to
                        # match the supplied binary or not. Should the
                        # comparison fail, we mark this build as a failure
                        # and remove everything from the unsigned folder.
                        with tempfile.TemporaryDirectory() as tmp_dir:
                            unsigned_apk = \
                                common.get_release_filename(app, build)
                            unsigned_apk = \
                                os.path.join(output_dir, unsigned_apk)
                            compare_result = \
                                common.verify_apks(of, unsigned_apk, tmp_dir)
                            if compare_result:
                                if options.test:
                                    logging.warning(_('Keeping failed build "{apkfilename}"')
                                                    .format(apkfilename=unsigned_apk))
                                else:
                                    logging.debug('removing %s', unsigned_apk)
                                    os.remove(unsigned_apk)
                                logging.debug('removing %s', of)
                                os.remove(of)
                                compare_result = compare_result.split('\n')
                                line_count = len(compare_result)
                                compare_result = compare_result[:299]
                                if line_count > len(compare_result):
                                    line_difference = \
                                        line_count - len(compare_result)
                                    compare_result.append('%d more lines ...' %
                                                          line_difference)
                                compare_result = '\n'.join(compare_result)
                                raise FDroidException('compared built binary '
                                                      'to supplied reference '
                                                      'binary but failed',
                                                      compare_result)
                            else:
                                logging.info('compared built binary to '
                                             'supplied reference binary '
                                             'successfully')

                    build_succeeded.append(app)
                    build_succeeded_ids.append([app['id'], build.versionCode])
                    wiki_log = "Build succeeded"

            except VCSException as vcse:
                reason = str(vcse).split('\n', 1)[0] if options.verbose else str(vcse)
                logging.error("VCS error while building app %s: %s" % (
                    app_id, reason))
                if options.stop:
                    logging.debug("Error encountered, stopping by user request.")
                    common.force_exit(1)
                add_failed_builds_entry(failed_builds, app_id, build, vcse)
                wiki_log = str(vcse)
                common.deploy_build_log_with_rsync(app_id, build.versionCode, str(vcse))
            except FDroidException as e:
                with open(os.path.join(log_dir, app_id + '.log'), 'a+') as f:
                    f.write('\n\n============================================================\n')
                    f.write('versionCode: %s\nversionName: %s\ncommit: %s\n' %
                            (build.versionCode, build.versionName, build.commit))
                    f.write('Build completed at '
                            + common.get_wiki_timestamp() + '\n')
                    f.write('\n' + tools_version_log + '\n')
                    f.write(str(e))
                logging.error("Could not build app %s: %s" % (app_id, e))
                if options.stop:
                    logging.debug("Error encountered, stopping by user request.")
                    common.force_exit(1)
                add_failed_builds_entry(failed_builds, app_id, build, e)
                wiki_log = e.get_wikitext()
            except Exception as e:
                logging.error("Could not build app %s due to unknown error: %s" % (
                    app_id, traceback.format_exc()))
                if options.stop:
                    logging.debug("Error encountered, stopping by user request.")
                    common.force_exit(1)
                add_failed_builds_entry(failed_builds, app_id, build, e)
                wiki_log = str(e)

            if options.wiki and wiki_log:
                try:
                    # Write a page with the last build log for this version code
                    last_build_page = app_id + '/lastbuild_' + build.versionCode
                    new_page = site.Pages[last_build_page]
                    with open(os.path.join('tmp', 'fdroidserverid')) as fp:
                        fdroidserver_id = fp.read().rstrip()
                    txt = "* build session started at " + common.get_wiki_timestamp(start_timestamp) + '\n' \
                          + "* this build started at " + build_start_time + '\n' \
                          + "* this build completed at " + common.get_wiki_timestamp() + '\n' \
                          + common.get_git_describe_link() \
                          + '* fdroidserverid: [https://gitlab.com/fdroid/fdroidserver/commit/' \
                          + fdroidserver_id + ' ' + fdroidserver_id + ']\n\n'
                    if buildserver_id:
                        txt += '* buildserverid: [https://gitlab.com/fdroid/fdroidserver/commit/' \
                               + buildserver_id + ' ' + buildserver_id + ']\n\n'
                    txt += tools_version_log + '\n\n'
                    txt += '== Build Log ==\n\n' + wiki_log
                    new_page.save(txt, summary='Build log')
                    # Redirect from /lastbuild to the most recent build log
                    new_page = site.Pages[app_id + '/lastbuild']
                    new_page.save('#REDIRECT [[' + last_build_page + ']]', summary='Update redirect')
                except Exception as e:
                    logging.error("Error while attempting to publish build log: %s" % e)

            if timer:
                timer.cancel()  # kill the watchdog timer

        if max_build_time_reached:
            status_output['maxBuildTimeReached'] = True
            logging.info("Stopping after global build timeout...")
            break

    for app in build_succeeded:
        logging.info("success: %s" % (app.id))

    if not options.verbose:
        for fb in failed_builds:
            logging.info('Build for app {}:{} failed:\n{}'.format(*fb))

    logging.info(_("Finished"))
    if len(build_succeeded) > 0:
        logging.info(ngettext("{} build succeeded",
                              "{} builds succeeded", len(build_succeeded)).format(len(build_succeeded)))
    if len(failed_builds) > 0:
        logging.info(ngettext("{} build failed",
                              "{} builds failed", len(failed_builds)).format(len(failed_builds)))

    if options.wiki:
        wiki_page_path = 'build_' + time.strftime('%s', start_timestamp)
        new_page = site.Pages[wiki_page_path]
        txt = ''
        txt += "* command line: <code>%s</code>\n" % ' '.join(sys.argv)
        txt += "* started at %s\n" % common.get_wiki_timestamp(start_timestamp)
        txt += "* completed at %s\n" % common.get_wiki_timestamp()
        if buildserver_id:
            txt += ('* buildserverid: [https://gitlab.com/fdroid/fdroidserver/commit/{id} {id}]\n'
                    .format(id=buildserver_id))
        if fdroidserver_id:
            txt += ('* fdroidserverid: [https://gitlab.com/fdroid/fdroidserver/commit/{id} {id}]\n'
                    .format(id=fdroidserver_id))
        if os.cpu_count():
            txt += "* host processors: %d\n" % os.cpu_count()
            status_output['hostOsCpuCount'] = os.cpu_count()
        if os.path.isfile('/proc/meminfo') and os.access('/proc/meminfo', os.R_OK):
            with open('/proc/meminfo') as fp:
                for line in fp:
                    m = re.search(r'MemTotal:\s*([0-9].*)', line)
                    if m:
                        txt += "* host RAM: %s\n" % m.group(1)
                        status_output['hostProcMeminfoMemTotal'] = m.group(1)
                        break
        fdroid_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
        buildserver_config = os.path.join(fdroid_path, 'makebuildserver.config.py')
        if os.path.isfile(buildserver_config) and os.access(buildserver_config, os.R_OK):
            with open(buildserver_config) as configfile:
                for line in configfile:
                    m = re.search(r'cpus\s*=\s*([0-9].*)', line)
                    if m:
                        txt += "* guest processors: %s\n" % m.group(1)
                        status_output['guestVagrantVmCpus'] = m.group(1)
                    m = re.search(r'memory\s*=\s*([0-9].*)', line)
                    if m:
                        txt += "* guest RAM: %s MB\n" % m.group(1)
                        status_output['guestVagrantVmMemory'] = m.group(1)
        txt += "* successful builds: %d\n" % len(build_succeeded)
        txt += "* failed builds: %d\n" % len(failed_builds)
        txt += "\n\n"
        new_page.save(txt, summary='Run log')
        new_page = site.Pages['build']
        new_page.save('#REDIRECT [[' + wiki_page_path + ']]', summary='Update redirect')

    if buildserver_id:
        status_output['buildserver'] = {'commitId': buildserver_id}

    if not options.onserver:
        common.write_status_json(status_output)

    # hack to ensure this exits, even is some threads are still running
    common.force_exit()


if __name__ == "__main__":
    main()
