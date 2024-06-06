import os
import re
import sys
import glob
import shutil
import logging
import pathlib
import tarfile
import argparse
import traceback

import fdroidserver.common
import fdroidserver.metadata
import fdroidserver.exception

from fdroidserver import _


def rlimit_check(apps_count=1):
    """Make sure linux is confgured to allow for enough simultaneously oepn files.

    TODO: check if this is obsolete

    Parameters
    ----------
    apps_count
        In the past this used to be `len(apps)` In this context we're
        always buidling just one app so this is always 1
    """
    try:
        import resource  # not available on Windows

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if apps_count > soft:
            try:
                soft = apps_count * 2
                if soft > hard:
                    soft = hard
                resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
                logging.debug(
                    _('Set open file limit to {integer}').format(integer=soft)
                )
            except (OSError, ValueError) as e:
                logging.warning(_('Setting open file limit failed: ') + str(e))
    except ImportError:
        pass


def install_ndk(build, config):
    """Make sure the requested NDK version is or gets installed.

    TODO: check if this should be moved to a script that runs before starting
    the build. e.g. `build_local_prepare` or `build_local_sudo`

    Parameters
    ----------
    build
        Metadata build entry that's about the build and may contain the
        requested NDK version
    config
        dictonariy holding config/default data from `./config.yml`
    """
    ndk_path = build.ndk_path()
    if build.ndk or (build.buildjni and build.buildjni != ['no']):
        if not ndk_path:
            logging.warning("Android NDK version '%s' could not be found!" % build.ndk)
            logging.warning("Configured versions:")
            for k, v in config['ndk_paths'].items():
                if k.endswith("_orig"):
                    continue
                logging.warning("  %s: %s" % (k, v))
            fdroidserver.common.auto_install_ndk(build)
        elif not os.path.isdir(ndk_path):
            logging.critical("Android NDK '%s' is not a directory!" % ndk_path)
            raise fdroidserver.exception.FDroidException()
    return ndk_path


def get_build_root_dir(app, build):
    if build.subdir:
        return os.path.join(fdroidserver.common.get_build_dir(app), build.subdir)
    return fdroidserver.common.get_build_dir(app)


def transform_first_char(string, method):
    """Use method() on the first character of string."""
    if len(string) == 0:
        return string
    if len(string) == 1:
        return method(string)
    return method(string[0]) + string[1:]


def get_flavours_cmd(build):
    """Get flavor string, preformatted for gradle cli.

    Reads build flavors form metadata if any and reformats and concatenates
    them to be ready for use as CLI arguments to gradle. This will treat the
    vlue 'yes' as if there were not particular build flavor selected.

    Parameters
    ----------
    build
        The metadata build entry you'd like to read flavors from

    Returns
    -------
    A string containing the build flavor for this build. If it's the default
    flavor ("yes" in metadata) this returns an empty string. Returns None if
    it's not a gradle build.
    """
    flavours = build.gradle

    if flavours == ['yes']:
        flavours = []

    flavours_cmd = ''.join(
        [transform_first_char(flav, str.upper) for flav in flavours]
    )

    return flavours_cmd


def init_build(app, build, config):
    root_dir = get_build_root_dir(app, build)

    p = None
    gradletasks = []

    # We need to clean via the build tool in case the binary dirs are
    # different from the default ones

    bmethod = build.build_method()
    if bmethod == 'maven':
        logging.info("Cleaning Maven project...")
        cmd = [config['mvn3'], 'clean', '-Dandroid.sdk.path=' + config['sdk_path']]

        if '@' in build.maven:
            maven_dir = os.path.join(root_dir, build.maven.split('@', 1)[1])
            maven_dir = os.path.normpath(maven_dir)
        else:
            maven_dir = root_dir

        p = fdroidserver.common.FDroidPopen(cmd, cwd=maven_dir)

    elif bmethod == 'gradle':

        logging.info("Cleaning Gradle project...")

        if build.preassemble:
            gradletasks += build.preassemble

        flavours_cmd = get_flavours_cmd(build)

        gradletasks += ['assemble' + flavours_cmd + 'Release']

        cmd = [config['gradle']]
        if build.gradleprops:
            cmd += ['-P' + kv for kv in build.gradleprops]

        cmd += ['clean']
        p = fdroidserver.common.FDroidPopen(
            cmd,
            cwd=root_dir,
            envs={
                "GRADLE_VERSION_DIR": config['gradle_version_dir'],
                "CACHEDIR": config['cachedir'],
            },
        )

    elif bmethod == 'ant':
        logging.info("Cleaning Ant project...")
        p = fdroidserver.common.FDroidPopen(['ant', 'clean'], cwd=root_dir)

    if p is not None and p.returncode != 0:
        raise fdroidserver.exception.BuildException(
            "Error cleaning %s:%s" % (app.id, build.versionName), p.output
        )

    return gradletasks


def sanitize_build_dir(app):
    """Delete build output directories.

    This function deletes the default build/binary/target/... output
    directories for follwoing build tools: gradle, maven, ant, jni. It also
    deletes gradle-wrapper if present. It just uses parths, hardcoded here,
    it doesn't call and build system clean routines.

    Parameters
    ----------
    app
        The metadata of the app to sanitize
    """
    build_dir = fdroidserver.common.get_build_dir(app)
    for root, dirs, files in os.walk(build_dir):

        def del_dirs(dl):
            for d in dl:
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)

        def del_files(fl):
            for f in fl:
                if f in files:
                    os.remove(os.path.join(root, f))

        if any(
            f in files
            for f in [
                'build.gradle',
                'build.gradle.kts',
                'settings.gradle',
                'settings.gradle.kts',
            ]
        ):
            # Even when running clean, gradle stores task/artifact caches in
            # .gradle/ as binary files. To avoid overcomplicating the scanner,
            # manually delete them, just like `gradle clean` should have removed
            # the build/* dirs.
            del_dirs(
                [
                    os.path.join('build', 'android-profile'),
                    os.path.join('build', 'generated'),
                    os.path.join('build', 'intermediates'),
                    os.path.join('build', 'outputs'),
                    os.path.join('build', 'reports'),
                    os.path.join('build', 'tmp'),
                    os.path.join('buildSrc', 'build'),
                    '.gradle',
                ]
            )
            del_files(['gradlew', 'gradlew.bat'])

        if 'pom.xml' in files:
            del_dirs(['target'])

        if any(
            f in files for f in ['ant.properties', 'project.properties', 'build.xml']
        ):
            del_dirs(['bin', 'gen'])

        if 'jni' in dirs:
            del_dirs(['obj'])


def make_tarball(app, build, tmp_dir):
    build_dir = fdroidserver.common.get_build_dir(app)
    # Build the source tarball right before we build the release...
    logging.info("Creating source tarball...")
    tarname = fdroidserver.common.getsrcname(app, build)
    tarball = tarfile.open(os.path.join(tmp_dir, tarname), "w:gz")

    def tarexc(t):
        return (
            None
            if any(t.name.endswith(s) for s in ['.svn', '.git', '.hg', '.bzr'])
            else t
        )

    tarball.add(build_dir, tarname, filter=tarexc)
    tarball.close()


def execute_build_commands(app, build):
    """Execute `bulid` commands if present in metadata.

    see: https://f-droid.org/docs/Build_Metadata_Reference/#build_build

    Parameters
    ----------
    app
        metadata app object
    build
        metadata build object
    """
    root_dir = get_build_root_dir(app, build)
    srclibpaths = get_srclibpaths(app, build)

    if build.build:
        logging.info("Running 'build' commands in %s" % root_dir)
        cmd = fdroidserver.common.replace_config_vars("; ".join(build.build), build)

        # Substitute source library paths into commands...
        for name, number, libpath in srclibpaths:
            cmd = cmd.replace('$$' + name + '$$', os.path.join(os.getcwd(), libpath))

        p = fdroidserver.common.FDroidPopen(
            ['bash', '-e', '-u', '-o', 'pipefail', '-x', '-c', cmd], cwd=root_dir
        )

        if p.returncode != 0:
            raise fdroidserver.exception.BuildException(
                "Error running build command for %s:%s" % (app.id, build.versionName),
                p.output,
            )


def get_srclibpaths(app, build):
    """Get srclibpaths list of tuples.

    This will just assemble the srclibpaths list of tuples, it won't fetch
    or checkout any source code, identical to return value of
    common.prepare_souce().

    Parameters
    ----------
    app
        metadata app object
    build
        metadata build object

    Returns
    -------
    List of srclibpath tuples
    """
    vcs, _ = fdroidserver.common.setup_vcs(app)

    srclibpaths = []
    if build.srclibs:
        logging.info("Collecting source libraries")
        for lib in build.srclibs:
            srclibpaths.append(
                fdroidserver.common.getsrclib(
                    lib, "./build/srclib", prepare=False, refresh=False, build=build
                )
            )

    basesrclib = vcs.getsrclib()
    if basesrclib:
        srclibpaths.append(basesrclib)

    return srclibpaths


def execute_buildjni_commands(app, build, ndk_path):
    root_dir = get_build_root_dir(app, build)
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
            p = fdroidserver.common.FDroidPopen(cmd, cwd=os.path.join(root_dir, d))
            if p.returncode != 0:
                raise fdroidserver.exception.BuildException(
                    "NDK build failed for %s:%s" % (app.id, build.versionName), p.output
                )


def execute_build(app, build, config, gradletasks):
    root_dir = get_build_root_dir(app, build)

    p = None
    bindir = None
    bmethod = build.build_method()
    if bmethod == 'maven':
        logging.info("Building Maven project...")

        if '@' in build.maven:
            maven_dir = os.path.join(root_dir, build.maven.split('@', 1)[1])
        else:
            maven_dir = root_dir

        mvncmd = [
            config['mvn3'],
            '-Dandroid.sdk.path=' + config['sdk_path'],
            '-Dmaven.jar.sign.skip=true',
            '-Dmaven.test.skip=true',
            '-Dandroid.sign.debug=false',
            '-Dandroid.release=true',
            'package',
        ]
        if build.target:
            target = build.target.split('-')[1]
            fdroidserver.common.regsub_file(
                r'<platform>[0-9]*</platform>',
                r'<platform>%s</platform>' % target,
                os.path.join(root_dir, 'pom.xml'),
            )
            if '@' in build.maven:
                fdroidserver.common.regsub_file(
                    r'<platform>[0-9]*</platform>',
                    r'<platform>%s</platform>' % target,
                    os.path.join(maven_dir, 'pom.xml'),
                )

        p = fdroidserver.common.FDroidPopen(mvncmd, cwd=maven_dir)

        bindir = os.path.join(root_dir, 'target')

    elif bmethod == 'gradle':
        logging.info("Building Gradle project...")

        cmd = [config['gradle']]
        if build.gradleprops:
            cmd += ['-P' + kv for kv in build.gradleprops]

        cmd += gradletasks

        p = fdroidserver.common.FDroidPopen(
            cmd,
            cwd=root_dir,
            envs={
                "GRADLE_VERSION_DIR": config['gradle_version_dir'],
                "CACHEDIR": config['cachedir'],
            },
        )

    elif bmethod == 'ant':
        logging.info("Building Ant project...")
        cmd = ['ant']
        if build.antcommands:
            cmd += build.antcommands
        else:
            cmd += ['release']
        p = fdroidserver.common.FDroidPopen(cmd, cwd=root_dir)

        bindir = os.path.join(root_dir, 'bin')

    return p, bindir


def collect_build_output(app, build, p, bindir):
    root_dir = get_build_root_dir(app, build)

    omethod = build.output_method()
    src = None
    if omethod == 'maven':
        stdout_apk = '\n'.join(
            [
                line
                for line in p.output.splitlines()
                if any(a in line for a in ('.apk', '.ap_', '.jar'))
            ]
        )
        m = re.match(
            r".*^\[INFO\] .*apkbuilder.*/([^/]*)\.apk", stdout_apk, re.S | re.M
        )
        if not m:
            m = re.match(
                r".*^\[INFO\] Creating additional unsigned apk file .*/([^/]+)\.apk[^l]",
                stdout_apk,
                re.S | re.M,
            )
        if not m:
            m = re.match(
                r'.*^\[INFO\] [^$]*aapt \[package,[^$]*'
                + bindir
                + r'/([^/]+)\.ap[_k][,\]]',
                stdout_apk,
                re.S | re.M,
            )

        if not m:
            m = re.match(
                r".*^\[INFO\] Building jar: .*/" + bindir + r"/(.+)\.jar",
                stdout_apk,
                re.S | re.M,
            )
        if not m:
            raise fdroidserver.exception.BuildException('Failed to find output')
        src = m.group(1)
        src = os.path.join(bindir, src) + '.apk'

    elif omethod == 'gradle':
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
        flavours_cmd = get_flavours_cmd(build)
        if flavours_cmd:
            apk_dirs.append(
                os.path.join(
                    root_dir,
                    'build',
                    'outputs',
                    'apk',
                    transform_first_char(flavours_cmd, str.lower),
                    'release',
                )
            )
        for apks_dir in apk_dirs:
            for apkglob in ['*-release-unsigned.apk', '*-unsigned.apk', '*.apk']:
                apks = glob.glob(os.path.join(apks_dir, apkglob))

                if len(apks) > 1:
                    raise fdroidserver.exception.BuildException(
                        'More than one resulting apks found in %s' % apks_dir,
                        '\n'.join(apks),
                    )
                if len(apks) == 1:
                    src = apks[0]
                    break
            if src is not None:
                break

        if src is None:
            raise fdroidserver.exception.BuildException(
                'Failed to find any output apks'
            )

    elif omethod == 'ant':
        stdout_apk = '\n'.join(
            [line for line in p.output.splitlines() if '.apk' in line]
        )
        src = re.match(
            r".*^.*Creating (.+) for release.*$.*", stdout_apk, re.S | re.M
        ).group(1)
        src = os.path.join(bindir, src)
    elif omethod == 'raw':
        output_path = fdroidserver.common.replace_build_vars(build.output, build)
        globpath = os.path.join(root_dir, output_path)
        apks = glob.glob(globpath)
        if len(apks) > 1:
            raise fdroidserver.exception.BuildException(
                'Multiple apks match %s' % globpath, '\n'.join(apks)
            )
        if len(apks) < 1:
            raise fdroidserver.exception.BuildException('No apks match %s' % globpath)
        src = os.path.normpath(apks[0])
    return src


def check_build_success(app, build, p):
    build_dir = fdroidserver.common.get_build_dir(app)

    if os.path.isdir(os.path.join(build_dir, '.git')):
        import git

        commit_id = fdroidserver.common.get_head_commit_id(git.repo.Repo(build_dir))
    else:
        commit_id = build.commit

    if p is not None and p.returncode != 0:
        raise fdroidserver.exception.BuildException(
            "Build failed for %s:%s@%s" % (app.id, build.versionName, commit_id),
            p.output,
        )
    logging.info(
        "Successfully built version {versionName} of {appid} from {commit_id}".format(
            versionName=build.versionName, appid=app.id, commit_id=commit_id
        )
    )


def execute_postbuild(app, build, src):
    root_dir = get_build_root_dir(app, build)
    srclibpaths = get_srclibpaths(app, build)

    if build.postbuild:
        logging.info(f"Running 'postbuild' commands in {root_dir}")
        cmd = fdroidserver.common.replace_config_vars("; ".join(build.postbuild), build)

        # Substitute source library paths into commands...
        for name, number, libpath in srclibpaths:
            cmd = cmd.replace(f"$${name}$$", str(pathlib.Path.cwd() / libpath))

        cmd = cmd.replace('$$OUT$$', str(pathlib.Path(src).resolve()))

        p = fdroidserver.common.FDroidPopen(
            ['bash', '-e', '-u', '-o', 'pipefail', '-x', '-c', cmd], cwd=root_dir
        )

        if p.returncode != 0:
            raise fdroidserver.exception.BuildException(
                "Error running postbuild command for " f"{app.id}:{build.versionName}",
                p.output,
            )


def get_metadata_from_apk(app, build, apkfile):
    """Get the required metadata from the built APK.

    VersionName is allowed to be a blank string, i.e. ''

    Parameters
    ----------
    app
        The app metadata used to build the APK.
    build
        The build that resulted in the APK.
    apkfile
        The path of the APK file.

    Returns
    -------
    versionCode
        The versionCode from the APK or from the metadata is build.novcheck is
        set.
    versionName
        The versionName from the APK or from the metadata is build.novcheck is
        set.

    Raises
    ------
    :exc:`~fdroidserver.exception.BuildException`
        If native code should have been built but was not packaged, no version
        information or no package ID could be found or there is a mismatch
        between the package ID in the metadata and the one found in the APK.
    """
    appid, versionCode, versionName = fdroidserver.common.get_apk_id(apkfile)
    native_code = fdroidserver.common.get_native_code(apkfile)

    if build.buildjni and build.buildjni != ['no'] and not native_code:
        raise fdroidserver.exception.BuildException(
            "Native code should have been built but none was packaged"
        )
    if build.novcheck:
        versionCode = build.versionCode
        versionName = build.versionName
    if not versionCode or versionName is None:
        raise fdroidserver.exception.BuildException(
            "Could not find version information in build in output"
        )
    if not appid:
        raise fdroidserver.exception.BuildException(
            "Could not find package ID in output"
        )
    if appid != app.id:
        raise fdroidserver.exception.BuildException(
            "Wrong package ID - build " + appid + " but expected " + app.id
        )

    return versionCode, versionName


def validate_build_artifacts(app, build, src):
    # Make sure it's not debuggable...
    if fdroidserver.common.is_debuggable_or_testOnly(src):
        raise fdroidserver.exception.BuildException(
            "%s: debuggable or testOnly set in AndroidManifest.xml" % src
        )

    # By way of a sanity check, make sure the version and version
    # code in our new APK match what we expect...
    logging.debug("Checking " + src)
    if not os.path.exists(src):
        raise fdroidserver.exception.BuildException(
            "Unsigned APK is not at expected location of " + src
        )

    if fdroidserver.common.get_file_extension(src) == 'apk':
        vercode, version = get_metadata_from_apk(app, build, src)
        if version != build.versionName or vercode != build.versionCode:
            raise fdroidserver.exception.BuildException(
                (
                    "Unexpected version/version code in output;"
                    " APK: '%s' / '%d', "
                    " Expected: '%s' / '%d'"
                )
                % (version, vercode, build.versionName, build.versionCode)
            )


def move_build_output(app, build, src, tmp_dir, output_dir="unsigned", notarball=False):
    tarname = fdroidserver.common.getsrcname(app, build)

    # Copy the unsigned APK to our destination directory for further
    # processing (by publish.py)...
    dest = os.path.join(
        output_dir,
        fdroidserver.common.get_release_filename(
            app, build, fdroidserver.common.get_file_extension(src)
        ),
    )
    shutil.copyfile(src, dest)

    # Move the source tarball into the output directory...
    if output_dir != tmp_dir and not notarball:
        shutil.move(os.path.join(tmp_dir, tarname), os.path.join(output_dir, tarname))


def run_this_build(config, options, package_name, version_code):
    """Run build for one specific version of an app localy.

    :raises: various exceptions in case and of the pre-required conditions for the requested build are not met
    """
    app, build = fdroidserver.metadata.read_build_metadata(package_name, version_code)

    # not sure if this makes any sense to change open file limits since we know
    # that this script will only ever build one app
    rlimit_check()

    logging.info(
        "Building version %s (%s) of %s"
        % (build.versionName, build.versionCode, app.id)
    )

    # init fdroid Popen wrapper
    fdroidserver.common.set_FDroidPopen_env(build)
    gradletasks = init_build(app, build, config)

    sanitize_build_dir(app)

    # this is where we'd call scanner.scan_source() in old build.py

    # create tarball before building
    # consider  this optional?
    tmp_dir = pathlib.Path("./tmp")
    tmp_dir.mkdir(exist_ok=True)
    make_tarball(app, build, tmp_dir)

    # Run a build command if one is required...
    execute_build_commands(app, build)

    # Build native stuff if required...
    ndk_path = install_ndk(build, config)  # TODO: move to prepare step?
    execute_buildjni_commands(app, build, ndk_path)

    # Build the release...
    p, bindir = execute_build(app, build, config, gradletasks)
    check_build_success(app, build, p)
    src = collect_build_output(app, build, p, bindir)

    # Run a postbuild command if one is required...
    execute_postbuild(app, build, src)

    validate_build_artifacts(app, build, src)

    # this is where we'd call scanner.scan_binary() in old build.py

    move_build_output(app, build, src, tmp_dir)


def main():
    parser = argparse.ArgumentParser(
        description=_(
            "Build one specific in app. This command "
            "assumes all required build tools are installed and "
            "configured."
        )
    )
    parser.add_argument(
        "APP_VERSION",
        help=_("app id and version code tuple (e.g. org.fdroid.fdroid:1019051)"),
    )

    # fdroid args/opts boilerplate
    fdroidserver.common.setup_global_opts(parser)
    options = fdroidserver.common.parse_args(parser)
    config = fdroidserver.common.get_config()

    try:
        # read build target package name and version code from CLI arguments
        package_name, version_code = fdroidserver.common.split_pkg_arg(
            options.APP_VERSION
        )
        # trigger the build
        run_this_build(config, options, package_name, version_code)
    except Exception as e:
        if options.verbose:
            traceback.print_exc()
        else:
            print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
