#!/usr/bin/env python3
#
# build.py - part of the FDroid server tools
# Copyright (C) 2024, Michael Pöhn <michael@poehn.at>
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
import pathlib
import logging
import argparse

from fdroidserver import _
import fdroidserver.common


def sudo_run(app, build):
    # before doing anything, run the sudo commands to setup the VM
    if build.sudo:
        logging.info("Running 'sudo' commands in %s" % os.getcwd())

        p = fdroidserver.common.FDroidPopen(
            [
                'sudo',
                'DEBIAN_FRONTEND=noninteractive',
                'bash',
                '-e',
                '-u',
                '-o',
                'pipefail',
                '-x',
                '-c',
                '; '.join(build.sudo),
            ]
        )
        if p.returncode != 0:
            raise BuildException(
                "Error running sudo command for %s:%s" % (app.id, build.versionName),
                p.output,
            )


def sudo_lock_root(app, build):
    p = fdroidserver.common.FDroidPopen(['sudo', 'passwd', '--lock', 'root'])
    if p.returncode != 0:
        raise BuildException(
            "Error locking root account for %s:%s" % (app.id, build.versionName),
            p.output,
        )


def sudo_uninstall(app, build):
    p = fdroidserver.common.FDroidPopen(
        ['sudo', 'SUDO_FORCE_REMOVE=yes', 'dpkg', '--purge', 'sudo']
    )
    if p.returncode != 0:
        raise BuildException(
            "Error removing sudo for %s:%s" % (app.id, build.versionName), p.output
        )


def log_tools_version(app, build, log_dir):
    log_path = os.path.join(
        log_dir, fdroidserver.common.get_toolsversion_logname(app, build)
    )
    with open(log_path, 'w') as f:
        f.write(fdroidserver.common.get_android_tools_version_log())


def main():
    parser = argparse.ArgumentParser(
        description=_(
            "Download source code and initialize build environment "
            "for one specific build"
        ),
    )
    parser.add_argument(
        "--sudo-run",
        action="store_true",
        default=False,
        help=_("run commands listed in sudo-metadata"),
    )
    parser.add_argument(
        "--sudo-uninstall",
        action="store_true",
        default=False,
        help=_("uninstall sudo executing sudo-metadata"),
    )
    parser.add_argument(
        "--sudo-lock-root",
        action="store_true",
        default=False,
        help=_("lock root user account"),
    )
    parser.add_argument(
        "APP_VERSION",
        help=_("app id and version code tuple 'APPID:VERCODE'"),
    )

    # fdroid args/opts boilerplate
    fdroidserver.common.setup_global_opts(parser)
    options = fdroidserver.common.parse_args(parser)
    config = fdroidserver.common.get_config()

    package_name, version_code = fdroidserver.common.split_pkg_arg(options.APP_VERSION)
    app, build = fdroidserver.metadata.read_build_metadata(package_name, version_code)

    # prepare folders for git/vcs checkout
    vcs, build_dir = fdroidserver.common.setup_vcs(app)
    srclib_dir = pathlib.Path('./build/srclib')
    extlib_dir = pathlib.Path('./build/extlib')
    log_dir = pathlib.Path('./logs')
    output_dir = pathlib.Path('./unsigned')
    for d in (srclib_dir, extlib_dir, log_dir, output_dir):
        d.mkdir(exist_ok=True, parents=True)

    # run sudo stuff
    fdroidserver.common.set_FDroidPopen_env(build)
    if options.sudo_run:
        sudo_run(app, build)
    if options.sudo_lock_root:
        sudo_lock_root(app, build)
    if options.sudo_uninstall:
        sudo_uninstall(app, build)

    # TODO: in the past this was only logged when running as 'fdroid build
    # --onserver' is this this output still valuable or can we remove it?
    log_tools_version(app, build, log_dir)

    # do git/vcs checkout
    fdroidserver.common.prepare_source(
        vcs, app, build, build_dir, str(srclib_dir), str(extlib_dir)
    )

    # prepare for running cli commands
    # NOTE: unclear if this is required here
    # ndk_path = get_ndk_path(build)
    # fdroidserver.common.set_FDroidPopen_env(build)


if __name__ == "__main__":
    main()
