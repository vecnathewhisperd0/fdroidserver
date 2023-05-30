# SPDX-FileCopyrightText: 2023 Gregor Düster <git@gdstr.eu>
#
# SPDX-License-Identifier: AGPL-3.0

import argparse
import importlib
from pathlib import Path

import fdroidserver.__main__

MODULES = (
    "btlog",
    "build",
    "checkupdates",
    "deploy",
    "gpgsign",
    "import_subcommand",
    "init",
    "install",
    "lint",
    "mirror",
    "nightly",
    "publish",
    "readmeta",
    "rewritemeta",
    "scanner",
    "signatures",
    "signindex",
    "update",
    "verify",
)

lines = []

# Include header with functions
lines.append((Path(__file__).parent / "fish-completion_header.fish").read_text())

# Generate completion for subcommands
for command, description in fdroidserver.__main__.COMMANDS.items():
    lines.append(
        f"complete -c fdroid -n '__fish_use_subcommand' -f -a '{command}' -d '{description}'"
    )

# Generate completion for parameters of subcommands
for module in MODULES:
    for action in (
        importlib.import_module(f"fdroidserver.{module}").get_argument_parser()._actions
    ):
        # Module for fdroid import is named import_subcommand b/c import is a reserved Python keyword
        command = module.replace("_subcommand", "")

        if action.nargs not in (None, 0, "*", "?") or action.help == argparse.SUPPRESS:
            continue

        if action.nargs == "?":
            lines.append(
                f"complete -c fdroid -n '__fish_seen_subcommand_from {command}' -f"
            )
            continue

        if action.nargs == "*":
            args_command = "__fish_fdroid_package"
            if command == "scanner":
                args_command = "__fish_fdroid_scanner"
            elif command == "signatures":
                args_command = "__fish_fdroid_apk_files"
            elif command == "install":
                args_command = "__fish_fdroid_apk_package repo"
            elif command == "publish":
                args_command = "__fish_fdroid_apk_package unsigned"

            lines.append(
                f"complete -c fdroid -n '__fish_seen_subcommand_from {command}' -f -k -a '({args_command})'"
            )
            continue

        _option_strings = action.option_strings
        if len(_option_strings) not in (1, 2):
            raise ValueError("Number of option strings not in {1, 2}!")

        _short_option = _long_option = None
        if len(_option_strings) == 1:
            _option = _option_strings[0]
            if _option.startswith("--"):
                _long_option = _option
            else:
                _short_option = _option
        elif len(_option_strings) == 2:
            _short_option = _option_strings[0]
            _long_option = _option_strings[1]

        short_option = f" -s {_short_option.lstrip('-')}" if _short_option else ""
        long_option = f" -l {_long_option.lstrip('-')}" if _long_option else ""
        description = (
            " -d '"
            + f"{action.help[0].upper() + action.help[1:]}".replace("'", "\\'")
            + "'"
            if action.help
            else ""
        )

        lines.append(
            f"complete -c fdroid -n '__fish_seen_subcommand_from {command}'{short_option}{long_option}{description}"
        )

print("\n".join(lines))
