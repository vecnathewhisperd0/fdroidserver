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
            raise fdroidserver.exception.BuildException(
                "Error running sudo command for %s:%s" % (app.id, build.versionName),
                p.output,
            )


def sudo_lock_root(app, build):
    p = fdroidserver.common.FDroidPopen(['sudo', 'passwd', '--lock', 'root'])
    if p.returncode != 0:
        raise fdroidserver.exception.BuildException(
            "Error locking root account for %s:%s" % (app.id, build.versionName),
            p.output,
        )


def sudo_uninstall(app, build):
    p = fdroidserver.common.FDroidPopen(
        ['sudo', 'SUDO_FORCE_REMOVE=yes', 'dpkg', '--purge', 'sudo']
    )
    if p.returncode != 0:
        raise fdroidserver.exception.BuildException(
            "Error removing sudo for %s:%s" % (app.id, build.versionName), p.output
        )


def main():
    parser = argparse.ArgumentParser(
        description=_(
            """Run sudo commands """
        ),
    )
    parser.add_argument(
        "APP_VERSION",
        help=_("app id and version code tuple 'APPID:VERCODE'"),
    )

    # fdroid args/opts boilerplate
    fdroidserver.common.setup_global_opts(parser)
    options = fdroidserver.common.parse_args(parser)
    config = fdroidserver.common.get_config()
    config  # silcense pyflakes

    package_name, version_code = fdroidserver.common.split_pkg_arg(options.APP_VERSION)
    app, build = fdroidserver.metadata.read_build_metadata(package_name, version_code)


    # intialize FDroidPopen
    # TODO: remove once FDroidPopen is replaced with vm/container exec
    fdroidserver.common.set_FDroidPopen_env(build)

    # run sudo stuff
    sudo_run(app, build)
    sudo_lock_root(app, build)
    sudo_uninstall(app, build)

if __name__ == "__main__":
    main()
