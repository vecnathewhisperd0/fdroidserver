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
import sys
import json
import traceback
import argparse

from fdroidserver import _
import fdroidserver.common
import fdroidserver.metadata
import fdroidserver.update


def is_binary_artifact_present(appid, build):
    """Check if a build artifact/result form a previous run exists.

    Parameters
    ----------
    appid
        app id you're looking for (e.g. 'org.fdroid.fdroid')
    build
        metadata build object you're checking

    Returns
    -------
    True if a build artifact exists, otherwise False.
    """
    bin_dirs = ["archive", "repo", "unsigned"]
    ext = get_output_extension(build)

    for bin_dir in bin_dirs:
        if os.path.exists(f"./{bin_dir}/{appid}_{build.versionCode}.{ext}"):
            return True

    return False


def collect_schedule_entries(apps):
    """Get list of schedule entries for next build run.

    This function matches which builds in metadata are not built yet.

    Parameters
    ----------
    apps
        list of all metadata app objects of current repo

    Returns
    -------
    list of schedule entries
    """
    schedule = []
    for appid, app in apps.items():
        if not app.get("Disabled"):
            for build in app.get("Builds", {}):
                if not build.get("disable"):
                    if not is_binary_artifact_present(appid, build):
                        schedule.append(
                            {
                                "applicationId": appid,
                                "versionCode": build.get("versionCode"),
                                "timeout": build.get("timeout"),
                            }
                        )
    return schedule


# TODO remove this, and replace with this function from common.py
def get_output_extension(build):
    if build.output:
        return fdroidserver.common.get_file_extension(
            fdroidserver.common.replace_build_vars(build.output, build)
        )
    return 'apk'


def main():
    parser = argparse.ArgumentParser(
        description=_(""""""),
    )
    parser.add_argument(
        "--pretty",
        '-p',
        action="store_true",
        default=False,
        help="pretty output formatting",
    )

    # fdroid args/opts boilerplate
    fdroidserver.common.setup_global_opts(parser)
    options = fdroidserver.common.parse_args(parser)
    config = fdroidserver.common.get_config()
    config  # silcense pyflakes

    try:
        apps = fdroidserver.metadata.read_metadata()
        schedule = collect_schedule_entries(apps)

        indent = 2 if options.pretty else None
        print(json.dumps(schedule, indent=indent))
    except Exception as e:
        if options.verbose:
            traceback.print_exc()
        else:
            print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
