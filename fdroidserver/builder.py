import git
import logging
import shutil
import os
import re
import tarfile

from pathlib import Path
from gettext import ngettext

from . import build
from . import common
from . import metadata
from . import scanner

from .common import FDroidPopen
from .exception import FDroidException, BuildException


class Builder:
    bash_command = ['bash', '-e', '-u', '-o', 'pipefail', '-x', '-c']

    # pylint: disable=unused-argument
    def __init__(
        self,
        app: metadata.App,
        build: metadata.Build,
        config,
        options,
        vcs,
        build_dir: Path,
        output_dir: Path,
        log_dir: Path,
        srclib_dir: Path,
        extlib_dir: Path,
        tmp_dir: Path,
        force,
        onserver,
        refresh,
    ):
        self.__dict__.update(locals())

        # Optionally, the actual app source can be in a subdirectory
        # TODO: force subdir to be a str?
        if self.build.subdir:
            self.root_dir = self.build_dir / self.build.subdir
        else:
            self.root_dir = self.build_dir

    def check_build(self):
        """Check the build is valid."""
        if build_method := self.build.build_method() != 'raw':
            raise BuildException(f"Unknown build method: '{build_method}'")
        if not self.build.get('output'):
            raise BuildException("Error output is not specified")

    def setup_ndk(self):
        """Install NDK if needed."""
        build = self.build
        ndk_path = build.ndk_path()
        ndk_path = Path(ndk_path) if ndk_path else None
        if build.ndk or (build.buildjni and build.buildjni != ['no']):
            if not ndk_path:
                logging.warning(
                    f"Android NDK version '{build.ndk}' could not be found!"
                )
                logging.warning("Configured versions:")
                for k, v in self.config['ndk_paths'].items():
                    if k.endswith("_orig"):
                        continue
                    logging.warning(f"  {k}: {v}")
                if self.onserver:
                    common.auto_install_ndk(build)  # FIXME: Is ndk_path updated here?
                    # FIXME: config is updated in auto_install_ndk
                    if isinstance(build.ndk, str):
                        ndk_path = Path(self.config['ndk_paths'][build.ndk])
                    elif isinstance(build.ndk, list):
                        ndk_path = Path(self.config['ndk_paths'][build.ndk[0]])
                else:
                    raise FDroidException()
            elif not ndk_path.is_dir():
                logging.critical(f"Android NDK '{ndk_path}' is not a directory!")
                raise FDroidException()

        self.ndk_path = ndk_path

    def setup_env(self):
        """Set up environment variables."""
        # FIXME: do not use the global envs
        common.set_FDroidPopen_env(self.build)

    def run_sudo(self):
        """Run sudo script."""
        if not self.build.sudo:
            return

        logging.info(f"Running 'sudo' commands in {Path.cwd()}")

        p = FDroidPopen(
            ['sudo', 'DEBIAN_FRONTEND=noninteractive']
            + self.bash_command
            + ['; '.join(self.build.sudo)]
        )
        if p.returncode != 0:
            raise BuildException(
                f"Error running sudo command for "
                f"{self.app.id}:{self.build.versionName}",
                p.output,
            )

    def post_sudo(self):
        """Lock root account and remove sudo."""
        p = FDroidPopen(['sudo', 'passwd', '--lock', 'root'])
        if p.returncode != 0:
            raise BuildException(
                f"Error locking root account for "
                f"{self.app.id}:{self.build.versionName}",
                p.output,
            )

        p = FDroidPopen(['sudo', 'SUDO_FORCE_REMOVE=yes', 'dpkg', '--purge', 'sudo'])
        if p.returncode != 0:
            raise BuildException(
                f"Error removing sudo for {self.app.id}:{self.build.versionName}",
                p.output,
            )

        log_path = self.log_dir / common.get_toolsversion_logname(self.app, self.build)
        log_path.write_text(common.get_android_tools_version_log())

    def clean_source(self):
        """Remove artifacts from source code."""
        for root, dirs, files in os.walk(self.build_dir):

            def del_dirs(dl):
                for d in dl:
                    shutil.rmtree(os.path.join(root, d), ignore_errors=True)

            def del_files(fl):
                for f in fl:
                    if f in files:
                        (Path(root) / f).unlink()

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
                        Path('build') / 'android-profile',
                        Path('build') / 'generated',
                        Path('build') / 'intermediates',
                        Path('build') / 'outputs',
                        Path('build') / 'reports',
                        Path('build') / 'tmp',
                        Path('buildSrc') / 'build',
                        Path('.gradle'),
                    ]
                )
                del_files(['gradlew', 'gradlew.bat'])

            if 'pom.xml' in files:
                del_dirs(['target'])

            if any(
                f in files
                for f in ['ant.properties', 'project.properties', 'build.xml']
            ):
                del_dirs(['bin', 'gen'])

            if 'jni' in dirs:
                del_dirs(['obj'])

    def prepare_source(self):
        _, self.srclib_paths = common.prepare_source(
            self.vcs,
            self.app,
            self.build,
            str(self.build_dir),
            str(self.srclib_dir),
            str(self.extlib_dir),
            self.onserver,
            self.refresh,
        )
        self.clean_source()

    def scan_source(self):
        """Scan source code before building."""
        logging.info("Scanning source for common problems...")
        scanner.options = self.options  # pass verbose through
        count = scanner.scan_source(str(self.build_dir), self.build)
        if count > 0:
            if self.force:
                logging.warning(
                    ngettext(
                        'Scanner found {} problem', 'Scanner found {} problems', count
                    ).format(count)
                )
            else:
                raise BuildException(
                    ngettext(
                        "Can't build due to {} error while scanning",
                        "Can't build due to {} errors while scanning",
                        count,
                    ).format(count)
                )

    def build_tarball(self):
        """Build the source tarball."""
        logging.info("Creating source tarball...")
        tarname = common.getsrcname(self.app, self.build)
        tarball = tarfile.open(self.tmp_dir / tarname, "w:gz")

        def tarexc(t):
            return (
                None
                if any(t.name.endswith(s) for s in ['.svn', '.git', '.hg', '.bzr'])
                else t
            )

        tarball.add(self.build_dir, tarname, filter=tarexc)
        tarball.close()

    def run_build(self):
        """Run build script."""
        if not self.build.build:
            return

        logging.info(f"Running 'build' commands in {self.root_dir}")
        cmd = common.replace_config_vars("; ".join(self.build.build), self.build)

        # Substitute source library paths into commands...
        for name, _, libpath in self.srclib_paths:
            cmd = cmd.replace(f"$${name}$$", str(Path.cwd() / libpath))

        self.result = FDroidPopen(self.bash_command + [cmd], cwd=self.root_dir)

    def run_buildjni(self):
        """Build native code with ndk-build."""
        if not self.build.buildjni or self.build.buildjni == ['no']:
            return
        logging.info("Building the native code")
        jni_components = self.build.buildjni

        if jni_components == ['yes']:
            jni_components = ['']
        cmd = [str(self.ndk_path / "ndk-build"), "-j1"]
        for d in jni_components:
            if d:
                logging.info(f"Building native code in '{d}'")
            else:
                logging.info("Building native code in the main project")
            manifest = self.root_dir / d / 'AndroidManifest.xml'
            if manifest.is_file():
                # Read and write the whole AM.xml to fix newlines and avoid
                # the ndk r8c or later 'wordlist' errors. The outcome of this
                # under gnu/linux is the same as when using tools like
                # dos2unix, but the native python way is faster and will
                # work in non-unix systems.
                manifest.write_text(manifest.read_text())
            p = FDroidPopen(cmd, cwd=self.root_dir / d)
            if p.returncode != 0:
                raise BuildException(
                    f"NDK build failed for {self.app.id}:{self.build.versionName}",
                    p.output,
                )

    def get_output(self):
        """Find the path of the output apk."""
        output_path = common.replace_build_vars(self.build.output, self.build)
        outputs = self.root_dir.glob(output_path)
        if not (output := next(outputs, None)):
            raise BuildException(f"No apks match {output_path}")
        if next(outputs, None):
            raise BuildException(f"Multiple apks match {output_path}")

        self.output = output

    def post_build(self):
        if (self.build_dir / '.git').is_dir():
            commit_id = common.get_head_commit_id(git.repo.Repo(self.build_dir))
        else:
            commit_id = self.build.commit

        if self.result.returncode != 0:
            raise BuildException(
                f"Build failed for "
                f"{self.app.id}:{self.build.versionName}@{self.commit_id}",
                self.result.output,
            )

        self.get_output()

        logging.info(
            f"Successfully built version {self.build.versionName} "
            f"of {self.app.id} from {commit_id}"
        )

    def build_apk(self):
        """Build the apk."""
        self.run_build()
        self.post_build()

    def check_output(self):
        """Check the output apk."""
        # Make sure it's not debuggable...
        if common.is_apk_and_debuggable(str(self.output)):
            raise BuildException("APK is debuggable")

        # By way of a sanity check, make sure the version and version
        # code in our new APK match what we expect...
        # FIXME: What does this check?
        logging.debug(f"Checking {self.output}")
        if not self.output.is_file():
            raise BuildException(
                f"Unsigned APK is not at expected location of {self.output}"
            )

        if self.output.suffix.lower() == '.apk':
            appid, versionCode, versionName = common.get_apk_id(str(self.output))
            native_code = common.get_native_code(str(self.output))

            if (
                self.build.buildjni
                and self.build.buildjni != ['no']
                and not native_code
            ):
                raise BuildException(
                    "Native code should have been built but none was packaged"
                )
            if not versionCode or versionName is None:
                raise BuildException(
                    "Could not find version information in build in output"
                )
            if not appid:
                raise BuildException("Could not find package ID in output")
            if appid != self.app.id:
                raise BuildException(
                    f"Wrong package ID - build {appid} but expected {self.app.id}"
                )
            if not self.build.novcheck and (
                versionName != self.build.versionName
                or versionCode != self.build.versionCode
            ):
                raise BuildException(
                    (
                        "Unexpected version/version code in output;"
                        f" APK: '{versionName}' / '{versionCode}', "
                        f" Expected: '{self.build.versionName}' / '{self.build.versionCode}'"
                    )
                )
            if (
                self.options.scan_binary or self.config.get('scan_binary')
            ) and not self.options.skipscan:
                if scanner.scan_binary(str(self.output)):
                    raise BuildException("Found blocklisted packages in final apk!")

    def copy_output(self):
        """Copy the unsigned APK to our destination directory."""
        dest = self.output_dir / common.get_release_filename(
            self.app, self.build, self.output.suffix[1:]
        )
        shutil.copyfile(self.output, dest)

    def run(self):
        self.setup_ndk()
        self.setup_env()

        if self.onserver:
            self.run_sudo()
            self.post_sudo()
        else:
            if self.build.sudo:
                logging.warning(
                    f"""
                    {self.app.id}:{self.build.versionName} runs this on the buildserver with sudo:
                        {build.sudo}
                    These commands were skipped because fdroid build is not running on a dedicated build server.
                    """
                )

        self.prepare_source()

        self.scan_source()

        if not self.options.notarball:
            self.build_tarball()

        self.build_apk()

        self.check_output()
        self.copy_output()


class GradleBuilder(Builder):
    """Builder for Gradle."""

    @staticmethod
    def transform_first_char(string, method):
        """Use method() on the first character of string."""
        if len(string) == 0:
            return string
        if len(string) == 1:
            return method(string)
        return method(string[0]) + string[1:]

    def __init__(
        self,
        app: metadata.App,
        build: metadata.Build,
        config,
        options,
        vcs,
        build_dir: Path,
        output_dir: Path,
        log_dir: Path,
        srclib_dir: Path,
        extlib_dir: Path,
        tmp_dir: Path,
        force,
        onserver,
        refresh,
    ):
        args = locals()
        del args["self"]
        del args["__class__"]
        super().__init__(**args)

        self.gradle_cmd = [self.config['gradle']]
        if self.build.gradleprops:
            self.gradle_cmd += ['-P' + kv for kv in self.build.gradleprops]

        self.gradle_envs = {
            "GRADLE_VERSION_DIR": self.config['gradle_version_dir'],
            "CACHEDIR": self.config['cachedir'],
        }

        flavours = self.build.gradle
        if flavours == ['yes']:
            flavours = []

        self.flavours_cmd = ''.join(
            [self.transform_first_char(flav, str.upper) for flav in flavours]
        )

    def check_build(self):
        """Check the build is valid."""
        if build_method := self.build.build_method() != 'gradle':
            raise BuildException(f"Unknown build method: '{build_method}'")

    def clean_source(self):
        """Run gradle clean."""
        logging.info("Cleaning Gradle project...")

        p = FDroidPopen(
            self.gradle_cmd + ['clean'],
            cwd=self.root_dir,
            envs=self.gradle_envs,
        )

        if p.returncode != 0:
            raise BuildException(
                f"Error running gradle clean for "
                f"{self.app.id}:{self.build.versionName}",
                p.output,
            )

        super().clean_source()

    def get_output(self):
        if self.build.get("output"):
            super().get_output()
            return

        apk_dirs = [
            # gradle plugin >= 3.0
            self.root_dir / 'build/outputs/apk/release',
            # gradle plugin < 3.0 and >= 0.11
            self.root_dir / 'build/outputs/apk',
            # really old path
            self.root_dir / 'build/apk',
        ]
        # If we build with gradle flavours with gradle plugin >= 3.0 the APK will be in
        # a subdirectory corresponding to the flavour command used, but with different
        # capitalization.
        if self.flavours_cmd:
            apk_dirs.append(
                self.root_dir
                / 'build/outputs/apk'
                / self.transform_first_char(self.flavours_cmd, str.lower)
                / 'release'
            )
        for apk_dir in apk_dirs:
            for apkglob in ['*-release-unsigned.apk', '*-unsigned.apk', '*.apk']:
                apks = apk_dir.glob(apkglob)

                # No apk is found, try the next pattern
                if not (first := next(apks, None)):
                    continue
                if second := next(apks, None):
                    raise BuildException(
                        f"More than one resulting apks found in {apk_dir}",
                        f"{first}\n{second}",
                    )
                break
            else:
                # No apk is found, try the next dir
                continue
            break
        else:
            raise BuildException('Failed to find any output apks')

        self.output = first

    def build_apk(self):
        self.run_build()

        self.run_buildjni()

        logging.info("Building Gradle project...")

        gradletasks = self.build.preassemble
        gradletasks += ['assemble' + self.flavours_cmd + 'Release']

        self.result = FDroidPopen(
            self.gradle_cmd + gradletasks,
            cwd=self.root_dir,
            envs=self.gradle_envs,
        )

        self.post_build()


class AntBuilder(Builder):
    """Builder for Ant."""

    def __init__(
        self,
        app: metadata.App,
        build: metadata.Build,
        config,
        options,
        vcs,
        build_dir: Path,
        output_dir: Path,
        log_dir: Path,
        srclib_dir: Path,
        extlib_dir: Path,
        tmp_dir: Path,
        force,
        onserver,
        refresh,
    ):
        args = locals()
        del args["self"]
        del args["__class__"]
        super().__init__(**args)

        # TODO: add install ant to sudo

    def clean_source(self):
        """Run ant clean."""
        logging.info("Cleaning Ant project...")

        p = FDroidPopen(['ant', 'clean'], cwd=self.root_dir)

        if p.returncode != 0:
            raise BuildException(
                f"Error running ant clean for "
                f"{self.app.id}:{self.build.versionName}",
                p.output,
            )

        super().clean_source()

    def get_output(self):
        if self.build.get("output"):
            super().get_output()
            return

        stdout_apk = '\n'.join(
            [line for line in self.result.output.splitlines() if '.apk' in line]
        )
        output = re.match(
            r".*^.*Creating (.+) for release.*$.*", stdout_apk, re.S | re.M
        ).group(1)
        self.output = self.root_dir / 'bin' / output

    def build_apk(self):
        self.run_build()

        self.run_buildjni()

        logging.info("Building Ant project...")

        cmd = ['ant']
        if self.build.antcommands:
            cmd += self.build.antcommands
        else:
            cmd += ['release']

        self.result = FDroidPopen(cmd, cwd=self.root_dir)

        self.post_build()


class MavenBuilder(Builder):
    """Builder for Maven."""

    def __init__(
        self,
        app: metadata.App,
        build: metadata.Build,
        config,
        options,
        vcs,
        build_dir: Path,
        output_dir: Path,
        log_dir: Path,
        srclib_dir: Path,
        extlib_dir: Path,
        tmp_dir: Path,
        force,
        onserver,
        refresh,
    ):
        args = locals()
        del args["self"]
        del args["__class__"]
        super().__init__(**args)

        # TODO: add install maven to sudo

        self.bin_dir = self.root_dir / 'target'

        if '@' in self.build.maven:
            self.maven_dir = (
                self.root_dir / self.build.maven.split('@', 1)[1]
            ).resolve()
        else:
            self.maven_dir = self.root_dir

        self.maven_cmd = [
            self.config['mvn3'],
            '-Dandroid.sdk.path=' + self.config['sdk_path'],
        ]

    def clean_source(self):
        logging.info("Cleaning Maven project...")
        cmd = self.maven_cmd + ['clean']

        p = FDroidPopen(cmd, cwd=self.maven_dir)

        if p.returncode != 0:
            raise BuildException(
                f"Error running maven clean for "
                f"{self.app.id}:{self.build.versionName}",
                p.output,
            )

        super().clean_source()

    def get_output(self):
        if self.build.get("output"):
            super().get_output()
            return

        stdout_apk = '\n'.join(
            [
                line
                for line in self.result.output.splitlines()
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
                + self.bin_dir
                + r'/([^/]+)\.ap[_k][,\]]',
                stdout_apk,
                re.S | re.M,
            )

        if not m:
            m = re.match(
                r".*^\[INFO\] Building jar: .*/" + self.bin_dir + r"/(.+)\.jar",
                stdout_apk,
                re.S | re.M,
            )
        if not m:
            raise BuildException('Failed to find output')
        output = m.group(1)
        self.output = self.bin_dir / f"{output}.apk"

    def build_apk(self):
        self.run_build()

        self.run_buildjni()

        logging.info("Building Maven project...")

        cmd = self.maven_cmd + [
            '-Dmaven.jar.sign.skip=true',
            '-Dmaven.test.skip=true',
            '-Dandroid.sign.debug=false',
            '-Dandroid.release=true',
            'package',
        ]
        if self.build.target:
            target = self.build.target.split('-')[1]
            common.regsub_file(
                r'<platform>[0-9]*</platform>',
                r'<platform>%s</platform>' % target,
                self.root_dir / 'pom.xml',
            )
            if '@' in self.build.maven:
                common.regsub_file(
                    r'<platform>[0-9]*</platform>',
                    r'<platform>%s</platform>' % target,
                    self.maven_dir / 'pom.xml',
                )

        self.result = FDroidPopen(cmd, cwd=self.maven_dir)

        self.post_build()


# pylint: disable=unused-argument
def build_local(
    app,
    build,
    config,
    options,
    vcs,
    build_dir,
    output_dir,
    log_dir,
    srclib_dir,
    extlib_dir,
    tmp_dir,
    force,
    onserver,
    refresh,
):
    args = locals()
    for k in args.keys():
        if k.endswith("_dir"):
            args[k] = Path(args[k])

    if build.gradle:
        builder = GradleBuilder(**args)
    elif build.ant:
        builder = AntBuilder(**args)
    elif build.maven:
        builder = MavenBuilder(**args)
    else:
        builder = Builder(**args)

    builder.run()
