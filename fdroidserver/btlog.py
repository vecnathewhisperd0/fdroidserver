#!/usr/bin/env python3
#
# btlog.py - part of the FDroid server tools
# Copyright (C) 2017, Hans-Christoph Steiner <hans@eds.org>
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

# This is for creating a binary transparency log in a git repo for any
# F-Droid repo accessible via HTTP.  It is meant to run very often,
# even once a minute in a cronjob, so it uses HEAD requests and the
# HTTP ETag to check if the file has changed.  HEAD requests should
# not count against the download counts.  This pattern of a HEAD then
# a GET is what fdroidclient uses to avoid ETags being abused as
# cookies. This also uses the same HTTP User Agent as the F-Droid
# client app so its not easy for the server to distinguish this from
# the F-Droid client.


import collections
import glob
import json
import logging
import os
import shutil
import tempfile
import zipfile
from argparse import ArgumentParser

import defusedxml.minidom
import git
import requests

from . import _
from . import common
from . import deploy
from .exception import FDroidException

options = None


def make_binary_transparency_log(repo_dirs, bt_repo='binary_transparency', url=None, commit_title='fdroid update'):
    """Log the indexes in a standalone git repo to serve as a "binary
    transparency" log.
    See: https://www.eff.org/deeplinks/2014/02/open-letter-to-tech-companies
    """

    logging.info('Committing indexes to ' + bt_repo)
    if os.path.exists(os.path.join(bt_repo, '.git')):
        git_repo = git.Repo(bt_repo)
    else:
        if not os.path.exists(bt_repo):
            os.mkdir(bt_repo)
        git_repo = git.Repo.init(bt_repo)

        if not url:
            url = common.config['repo_url'].rstrip('/')
        with open(os.path.join(bt_repo, 'README.md'), 'w') as fp:
            fp.write("""
# Binary Transparency Log for %s

This is a log of the signed app index metadata.  This is stored in a
git repo, which serves as an imperfect append-only storage mechanism.
People can then check that any file that they received from that
F-Droid repository was a publicly released file.

For more info on this idea:
* https://wiki.mozilla.org/Security/Binary_Transparency
""" % url[:url.rindex('/')])  # strip '/repo'
        git_repo.index.add(['README.md', ])
        git_repo.index.commit('add README')

    for repo_dir in repo_dirs:
        cp_dir = os.path.join(bt_repo, repo_dir)
        if not os.path.exists(cp_dir):
            os.mkdir(cp_dir)
        for f in ('index.xml', 'index-v1.json'):
            repo_f = os.path.join(repo_dir, f)
            if not os.path.exists(repo_f):
                continue
            destination = os.path.join(cp_dir, f)
            if f.endswith('.xml'):
                doc = defusedxml.minidom.parse(repo_f)
                output = doc.toprettyxml(encoding='utf-8')
                with open(destination, 'wb') as file:
                    file.write(output)
            elif f.endswith('.json'):
                with open(repo_f) as fp:
                    output = json.load(fp, object_pairs_hook=collections.OrderedDict)
                with open(destination, 'w') as fp:
                    json.dump(output, fp, indent=2)
            git_repo.index.add([repo_f])
        for f in ('index.jar', 'index-v1.jar'):
            repo_f = os.path.join(repo_dir, f)
            if not os.path.exists(repo_f):
                continue
            destination = os.path.join(cp_dir, f)
            jar_in = zipfile.ZipFile(repo_f, 'r')
            jar_out = zipfile.ZipFile(destination, 'w')
            for info in jar_in.infolist():
                if info.filename.startswith('META-INF/'):
                    jar_out.writestr(info, jar_in.read(info.filename))
            jar_out.close()
            jar_in.close()
            git_repo.index.add([repo_f])

        output_files = []
        for root, dirs, files in os.walk(repo_dir):
            for f in files:
                output_files.append(os.path.relpath(os.path.join(root, f), repo_dir))
        output = collections.OrderedDict()
        for f in sorted(output_files):
            repo_file = os.path.join(repo_dir, f)
            stat = os.stat(repo_file)
            output[f] = (
                stat.st_size,
                stat.st_ctime_ns,
                stat.st_mtime_ns,
                stat.st_mode,
                stat.st_uid,
                stat.st_gid,
            )
        fs_log_file = os.path.join(cp_dir, 'filesystemlog.json')
        with open(fs_log_file, 'w') as fp:
            json.dump(output, fp, indent=2)
        git_repo.index.add([os.path.join(repo_dir, 'filesystemlog.json')])

        for f in glob.glob(os.path.join(cp_dir, '*.HTTP-headers.json')):
            git_repo.index.add([os.path.join(repo_dir, os.path.basename(f))])

    git_repo.index.commit(commit_title)


def main():
    global options

    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("--git-repo",
                        default=os.path.join(os.getcwd(), 'binary_transparency'),
                        help=_("Path to the git repo to use as the log"))
    parser.add_argument("-u", "--url", default='https://f-droid.org',
                        help=_("The base URL for the repo to log (default: https://f-droid.org)"))
    parser.add_argument("--git-remote", default=None,
                        help=_("Push the log to this git remote repository"))
    options = parser.parse_args()

    if options.verbose:
        logging.getLogger("requests").setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)
    else:
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    if not os.path.exists(options.git_repo):
        raise FDroidException(
            '"%s" does not exist! Create it, or use --git-repo' % options.git_repo
        )

    session = requests.Session()

    new_files = False
    repo_dirs = ('repo', 'archive')
    temp_dir_base = tempfile.mkdtemp(prefix='.fdroid-btlog-')
    for repo_dir in repo_dirs:
        # TODO read HTTP headers for ETag from git repo
        tempdir = os.path.join(temp_dir_base, repo_dir)
        os.makedirs(tempdir, exist_ok=True)
        git_repo_dir = os.path.join(options.git_repo, repo_dir)
        os.makedirs(git_repo_dir, exist_ok=True)
        for f in ('index.jar', 'index.xml', 'index-v1.jar', 'index-v1.json'):
            dl_file = os.path.join(tempdir, f)
            dl_url = options.url + '/' + repo_dir + '/' + f
            http_headers_file = os.path.join(git_repo_dir, f + '.HTTP-headers.json')

            headers = {'User-Agent': 'F-Droid 0.102.3'}
            etag = None
            if os.path.exists(http_headers_file):
                with open(http_headers_file) as fp:
                    etag = json.load(fp)['ETag']

            r = session.head(dl_url, headers=headers, allow_redirects=False)
            if r.status_code != 200:
                logging.debug(
                    'HTTP Response (' + str(r.status_code) + '), did not download ' + dl_url
                )
                continue
            if etag and etag == r.headers.get('ETag'):
                logging.debug('ETag matches, did not download ' + dl_url)
                continue

            r = session.get(dl_url, headers=headers, allow_redirects=False)
            if r.status_code == 200:
                with open(dl_file, 'wb') as file:
                    for chunk in r:
                        file.write(chunk)

                dump = dict()
                for k, v in r.headers.items():
                    dump[k] = v
                with open(http_headers_file, 'w') as fp:
                    json.dump(dump, fp, indent=2, sort_keys=True)
                new_files = True

    if new_files:
        os.chdir(temp_dir_base)
        make_binary_transparency_log(repo_dirs, options.git_repo, options.url, 'fdroid btlog')
    if options.git_remote:
        deploy.push_binary_transparency(options.git_repo, options.git_remote)
    shutil.rmtree(temp_dir_base, ignore_errors=True)


if __name__ == "__main__":
    main()
