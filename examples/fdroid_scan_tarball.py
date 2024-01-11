#!/usr/bin/env python3
#
# an fdroid plugin for scanning a fdroid source taball

import argparse
import tarfile
import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from fdroidserver import scanner, common, metadata, FDroidException

fdroid_summary = 'scan source tarballs generate by fdroidserver'


def main():
    parser = argparse.ArgumentParser(
        usage="%(prog)s [options] [FILEPATH FILEPATH ...]]"
    )
    common.setup_global_opts(parser)
    parser.add_argument("filepath", nargs='*', help="tarball filepath")
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    scanner.options = options
    for f in options.filepath:
        logging.info("Scanning " + f)
        if not Path(f).exists():
            logging.error("No such tarball file: " + f)
            continue

        # filename format: appid_vercode_src.tar.gz
        try:
            appid, vercode = (Path(f).name)[:-11].rsplit('_', 1)
        except ValueError:
            logging.error("Invalid tarball filename: " + f)
            continue
        if not vercode.isdigit():
            logging.error("Invalid tarball filename: " + f)
            continue
        vercode = int(vercode)

        try:
            app = metadata.read_metadata({appid: [vercode]})[appid]
        except FDroidException:
            logging.error("No corresponding appid for " + f)
            continue
        for b in app.get('Builds', []):
            if b.versionCode == vercode:
                build = b
                break
        else:
            logging.warn("No corresponding build block for " + f)
            continue

        # The tarball has been cleaned so the scandelete path is unused
        build.scandelete = []

        with TemporaryDirectory() as tmpdir:
            with tarfile.open(f) as tarball:
                tarball.extractall(tmpdir)
                # The root path can be the filename with or without the extension
                rootpath = [p for p in Path(tmpdir).glob('*')]
                if len(rootpath) == 1:
                    count = scanner.scan_source(str(Path(rootpath[0])), build)
                else:
                    logging.error("Unknown tarball structure: " + ' '.join(rootpath))
                    continue

        if count > 0:
            logging.error("{count} errors in {f}".format(count=count, f=f))


if __name__ == "__main__":
    main()
