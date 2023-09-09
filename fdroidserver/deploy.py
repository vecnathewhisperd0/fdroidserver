#!/usr/bin/env python3
#
# deploy.py - part of the FDroid server tools
# Copyright (C) 2010-15, Ciaran Gultnieks, ciaran@ciarang.com
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

import sys
import glob
import hashlib
import json
import os
import re
import subprocess
import time
import urllib
import yaml
from argparse import ArgumentParser
import logging
import shutil
from string import Template

from . import _
from . import common
from . import index
from .exception import FDroidException

config = None
options = None
start_timestamp = time.gmtime()

GIT_BRANCH = 'master'

BINARY_TRANSPARENCY_DIR = 'binary_transparency'

AUTO_S3CFG = '.fdroid-deploy-s3cfg'
USER_S3CFG = 's3cfg'
REMOTE_HOSTNAME_REGEX = re.compile(r'\W*\w+\W+(\w+).*')


def _get_index_excludes(repo_section):
    """Return the list of files to be synced last, since they finalize the deploy.

    The process of pushing all the new packages to the various
    services can take a while.  So the index files should be updated
    last.  That ensures that the package files are available when the
    client learns about them from the new index files.

    """
    indexes = [
        os.path.join(repo_section, 'entry.jar'),
        os.path.join(repo_section, 'entry.json'),
        os.path.join(repo_section, 'entry.json.asc'),
        os.path.join(repo_section, 'index-v1.jar'),
        os.path.join(repo_section, 'index-v1.json'),
        os.path.join(repo_section, 'index-v1.json.asc'),
        os.path.join(repo_section, 'index-v2.json'),
        os.path.join(repo_section, 'index-v2.json.asc'),
        os.path.join(repo_section, 'index.jar'),
        os.path.join(repo_section, 'index.xml'),
    ]
    index_excludes = []
    for f in indexes:
        index_excludes.append('--exclude')
        index_excludes.append(f)
    return index_excludes


def update_awsbucket(repo_section):
    """Upload the contents of the directory `repo_section` (including subdirectories) to the AWS S3 "bucket".

    The contents of that subdir of the
    bucket will first be deleted.

    Requires AWS credentials set in config.yml if s3cmd is not installed: awsaccesskeyid, awssecretkey
    """
    logging.debug('Syncing "' + repo_section + '" to Amazon S3 bucket "'
                  + config['awsbucket'] + '"')

    if common.set_command_in_config('s3cmd'):
        update_awsbucket_s3cmd(repo_section)
    else:
        if os.path.exists(USER_S3CFG):
            raise FDroidException(_('"{path}" exists but s3cmd is not installed!')
                                  .format(path=USER_S3CFG))
        update_awsbucket_libcloud(repo_section)


required_permissions = '''{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketAcl",
                "s3:GetBucketRequestPayment",
                "s3:GetCallerIdentity",
                "s3:CreateBucket",
                "s3:GetBucketCors",
                "s3:GetBucketPolicy",
                "s3:GetBucketLifecycle",
                "s3:GetBucketLocation",
                "s3:GetBucketLocation"
            ],
            "Resource": "arn:aws:s3:::$bucket_name"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:PutObjectAcl"
            ],
            "Resource": "arn:aws:s3:::$bucket_name/*"
        }
    ]
}
'''


def get_required_permission_policy(name):
    return Template(required_permissions).substitute(bucket_name=name)


def update_awsbucket_s3cmd(repo_section):
    """Upload using the CLI tool s3cmd, which provides rsync-like sync.

    The upload is done in multiple passes to reduce the chance of
    interfering with an existing client-server interaction.  In the
    first pass, only new files are uploaded.  In the second pass,
    changed files are uploaded, overwriting what is on the server.  On
    the third/last pass, the indexes are uploaded, and any removed
    files are deleted from the server.  The last pass is the only pass
    to use a full MD5 checksum of all files to detect changes.
    """
    logging.debug(_('Using s3cmd to sync with: {url}')
                  .format(url=config['awsbucket']))

    # copy s3cmd exit codes from https://raw.githubusercontent.com/s3tools/s3cmd/master/S3/ExitCodes.py
    # !!!!! DON'T export these codes directly even if S3 python package is installed on your system.
    # !!!!! The s3cmd can miss this source file in some distributions
    EX_OK = 0
    EX_GENERAL = 1
    EX_PARTIAL = 2  # some parts of the command succeeded, while others failed
    # EX_SERVERMOVED = 10  # 301: Moved permanantly & 307: Moved temp
    # EX_SERVERERROR = 11  # 400, 405, 411, 416, 417, 501: Bad request, 504: Gateway Time-out
    EX_NOTFOUND = 12  # 404: Not found
    # EX_CONFLICT = 13  # 409: Conflict (ex: bucket error)
    # EX_PRECONDITION = 14  # 412: Precondition failed
    EX_SERVICE = 15  # 503: Service not available or slow down
    # EX_USAGE = 64  # The command was used incorrectly (e.g. bad command line syntax)
    EX_DATAERR = 65  # Failed file transfer, upload or download
    # EX_SOFTWARE = 70  # internal software error (e.g. S3 error of unknown specificity)
    EX_OSERR = 71  # system error (e.g. out of memory)
    # EX_OSFILE = 72  # OS error (e.g. invalid Python version)
    EX_IOERR = 74  # An error occurred while doing I/O on some file.
    EX_TEMPFAIL = 75  # temporary failure (S3DownloadError or similar, retry later)
    EX_ACCESSDENIED = 77  # Insufficient permissions to perform the operation on S3
    EX_CONFIG = 78  # Configuration file error
    # EX_CONNECTIONREFUSED = 111  # TCP connection refused (e.g. connecting to a closed server port)
    # _EX_SIGNAL = 128
    # _EX_SIGINT = 2
    # EX_BREAK = _EX_SIGNAL + _EX_SIGINT  # Control-C (KeyboardInterrupt raised)

    def run_s3cmd(command, bucket_name_for_err_msg="YOUR_BUCKET_NAME"):
        retry_timeouts = [0, 0, 1, 1, 5, 30, 60]
        for current in retry_timeouts:
            time.sleep(current)
            s3cmd_exit_code = subprocess.call(command)
            if s3cmd_exit_code == EX_OK:
                return
            elif s3cmd_exit_code in [EX_GENERAL, EX_PARTIAL, EX_SERVICE, EX_DATAERR, EX_OSERR, EX_IOERR, EX_TEMPFAIL]:
                retry = "it was last try"
                if current + 1 != len(retry_timeouts):
                    retry = "retry in {retry} second".format(retry=retry_timeouts[current + 1])
                logging.debug('s3cmd exited with code {code};  {retry}'.format(
                    code=s3cmd_exit_code, retry=retry))
                continue
            elif s3cmd_exit_code == EX_ACCESSDENIED:
                raise FDroidException('s3cmd exited with code {code};'
                                      '\nRequired permissions:\n{required_permissions}'.
                                      format(code=s3cmd_exit_code,
                                             required_permissions=get_required_permission_policy(
                                                 bucket_name_for_err_msg)))
            elif s3cmd_exit_code == EX_CONFIG:
                raise FDroidException('s3cmd exited with code {code};'
                                      'probably it could not find credentials'.format(code=s3cmd_exit_code))
            elif s3cmd_exit_code == EX_NOTFOUND:
                raise FDroidException('s3cmd exited with code {code};'
                                      'probably the bucket doesn\'t exist'.format(code=s3cmd_exit_code))
            else:
                raise FDroidException('s3cmd exited with code {code}'.format(code=repo_section))

    configfilename = None
    # user should prefer provide credential in other way
    if 'awsaccesskeyid' in config or 'awssecretkey' in config:  # it's intended if only one present it will fail
        fd = os.open(AUTO_S3CFG, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        logging.debug(_('Creating "{path}" for configuring s3cmd.').format(path=AUTO_S3CFG))
        os.write(fd, '[default]\n'.encode('utf-8'))
        os.write(fd, ('access_key = ' + config['awsaccesskeyid'] + '\n').encode('utf-8'))
        os.write(fd, ('secret_key = ' + config['awssecretkey'] + '\n').encode('utf-8'))
        os.close(fd)
        configfilename = AUTO_S3CFG

    s3bucketurl = 's3://' + config['awsbucket']
    s3cmd = [config['s3cmd']]
    if configfilename is not None:
        s3cmd.append('--config=' + configfilename)

    # check if bucket
    run_s3cmd(s3cmd + ['info', s3bucketurl], bucket_name_for_err_msg=config['awsbucket'])

    s3cmd_sync = s3cmd + ['sync', '--acl-public']
    if options.verbose:
        s3cmd_sync += ['--verbose']
    if options.quiet:
        s3cmd_sync += ['--quiet']

    s3url = s3bucketurl + '/fdroid/'
    logging.debug('s3cmd sync new files in ' + repo_section + ' to ' + s3url)
    logging.debug(_('Running first pass with MD5 checking disabled'))
    excludes = _get_index_excludes(repo_section)
    run_s3cmd(s3cmd_sync
              + excludes
              + ['--no-check-md5', '--skip-existing', repo_section, s3url],
              bucket_name_for_err_msg=config['awsbucket']
              )

    logging.debug('s3cmd sync all files in ' + repo_section + ' to ' + s3url)

    run_s3cmd(s3cmd_sync + excludes + ['--no-check-md5', repo_section, s3url],
              bucket_name_for_err_msg=config['awsbucket'])

    logging.debug(_('s3cmd sync indexes {path} to {url} and delete')
                  .format(path=repo_section, url=s3url))
    s3cmd_sync.append('--delete-removed')
    s3cmd_sync.append('--delete-after')
    if options.no_checksum:
        s3cmd_sync.append('--no-check-md5')
    else:
        s3cmd_sync.append('--check-md5')
    run_s3cmd(s3cmd_sync + [repo_section, s3url], bucket_name_for_err_msg=config['awsbucket'])


def update_awsbucket_libcloud(repo_section):
    """No summary.

    Upload the contents of the directory `repo_section` (including
    subdirectories) to the AWS S3 "bucket".

    The contents of that subdir of the
    bucket will first be deleted.

    Requires AWS credentials set in config.yml: awsaccesskeyid, awssecretkey
    """
    logging.debug(_('using Apache libcloud to sync with {url}')
                  .format(url=config['awsbucket']))

    import libcloud.security
    libcloud.security.VERIFY_SSL_CERT = True
    from libcloud.storage.types import Provider, ContainerDoesNotExistError
    from libcloud.storage.providers import get_driver

    if not config.get('awsaccesskeyid') or not config.get('awssecretkey'):
        raise FDroidException(
            _('Since s3cmd is not installed, deploy.py is using Apache Libcloud as a fallback. '
              'For this, "awssecretkey" and "awsaccesskeyid" must be explicitly defined in config.yml.'))
    awsbucket = config['awsbucket']

    cls = get_driver(Provider.S3)
    driver = cls(config['awsaccesskeyid'], config['awssecretkey'])
    try:
        container = driver.get_container(container_name=awsbucket)
    except ContainerDoesNotExistError as e:
        raise FDroidException(
            _('Bucket {name} doesn\'t exist. Please create it manually with latest AWS S3 recommendations')
            .format(name=awsbucket)) from e

    upload_dir = 'fdroid/' + repo_section
    objs = dict()
    for obj in container.list_objects():
        if obj.name.startswith(upload_dir + '/'):
            objs[obj.name] = obj

    for root, dirs, files in os.walk(os.path.join(os.getcwd(), repo_section)):
        for name in files:
            upload = False
            file_to_upload = os.path.join(root, name)
            object_name = 'fdroid/' + os.path.relpath(file_to_upload, os.getcwd())
            if object_name not in objs:
                upload = True
            else:
                obj = objs.pop(object_name)
                if obj.size != os.path.getsize(file_to_upload):
                    upload = True
                else:
                    # if the sizes match, then compare by MD5
                    md5 = hashlib.md5()  # nosec AWS uses MD5
                    with open(file_to_upload, 'rb') as f:
                        while True:
                            data = f.read(8192)
                            if not data:
                                break
                            md5.update(data)
                    if obj.hash != md5.hexdigest():
                        s3url = 's3://' + awsbucket + '/' + obj.name
                        logging.info(' deleting ' + s3url)
                        if not driver.delete_object(obj):
                            logging.warning('Could not delete ' + s3url)
                        upload = True

            if upload:
                logging.debug(' uploading "' + file_to_upload + '"...')
                extra = {'acl': 'public-read'}
                if file_to_upload.endswith('.sig'):
                    extra['content_type'] = 'application/pgp-signature'
                elif file_to_upload.endswith('.asc'):
                    extra['content_type'] = 'application/pgp-signature'
                logging.info(' uploading ' + os.path.relpath(file_to_upload)
                             + ' to s3://' + awsbucket + '/' + object_name)
                with open(file_to_upload, 'rb') as iterator:
                    obj = driver.upload_object_via_stream(iterator=iterator,
                                                          container=container,
                                                          object_name=object_name,
                                                          extra=extra)
    # delete the remnants in the bucket, they do not exist locally
    while objs:
        object_name, obj = objs.popitem()
        s3url = 's3://' + awsbucket + '/' + object_name
        if object_name.startswith(upload_dir):
            logging.warning(' deleting ' + s3url)
            driver.delete_object(obj)
        else:
            logging.info(' skipping ' + s3url)


def update_serverwebroot(serverwebroot, repo_section):
    """Deploy the index files to the serverwebroot using rsync.

    Upload the first time without the index files and delay the
    deletion as much as possible.  That keeps the repo functional
    while this update is running.  Then once it is complete, rerun the
    command again to upload the index files.  Always using the same
    target with rsync allows for very strict settings on the receiving
    server, you can literally specify the one rsync command that is
    allowed to run in ~/.ssh/authorized_keys.  (serverwebroot is
    guaranteed to have a trailing slash in common.py)

    It is possible to optionally use a checksum comparison for
    accurate comparisons on different filesystems, for example, FAT
    has a low resolution timestamp

    """
    try:
        subprocess.run(['rsync', '--version'], capture_output=True, check=True)
    except Exception as e:
        raise FDroidException(
            _('rsync is missing or broken: {error}').format(error=e)
        ) from e
    rsyncargs = ['rsync', '--archive', '--delete-after', '--safe-links']
    if not options.no_checksum:
        rsyncargs.append('--checksum')
    if options.verbose:
        rsyncargs += ['--verbose']
    if options.quiet:
        rsyncargs += ['--quiet']
    if options.identity_file is not None:
        rsyncargs += ['-e', 'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i ' + options.identity_file]
    elif 'identity_file' in config:
        rsyncargs += ['-e', 'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i ' + config['identity_file']]
    logging.info('rsyncing ' + repo_section + ' to ' + serverwebroot)
    excludes = _get_index_excludes(repo_section)
    if subprocess.call(rsyncargs + excludes + [repo_section, serverwebroot]) != 0:
        raise FDroidException()
    if subprocess.call(rsyncargs + [repo_section, serverwebroot]) != 0:
        raise FDroidException()
    # upload "current version" symlinks if requested
    if config['make_current_version_link'] and repo_section == 'repo':
        links_to_upload = []
        for f in glob.glob('*.apk') \
                + glob.glob('*.apk.asc') + glob.glob('*.apk.sig'):
            if os.path.islink(f):
                links_to_upload.append(f)
        if len(links_to_upload) > 0:
            if subprocess.call(rsyncargs + links_to_upload + [serverwebroot]) != 0:
                raise FDroidException()


def sync_from_localcopy(repo_section, local_copy_dir):
    """Sync the repo from "local copy dir" filesystem to this box.

    In setups that use offline signing, this is the last step that
    syncs the repo from the "local copy dir" e.g. a thumb drive to the
    repo on the local filesystem.  That local repo is then used to
    push to all the servers that are configured.

    """
    logging.info('Syncing from local_copy_dir to this repo.')
    # trailing slashes have a meaning in rsync which is not needed here, so
    # make sure both paths have exactly one trailing slash
    common.local_rsync(options,
                       os.path.join(local_copy_dir, repo_section).rstrip('/') + '/',
                       repo_section.rstrip('/') + '/')

    offline_copy = os.path.join(local_copy_dir, BINARY_TRANSPARENCY_DIR)
    if os.path.exists(os.path.join(offline_copy, '.git')):
        online_copy = os.path.join(os.getcwd(), BINARY_TRANSPARENCY_DIR)
        push_binary_transparency(offline_copy, online_copy)


def update_localcopy(repo_section, local_copy_dir):
    """Copy data from offline to the "local copy dir" filesystem.

    This updates the copy of this repo used to shuttle data from an
    offline signing machine to the online machine, e.g. on a thumb
    drive.

    """
    # local_copy_dir is guaranteed to have a trailing slash in main() below
    common.local_rsync(options, repo_section, local_copy_dir)

    offline_copy = os.path.join(os.getcwd(), BINARY_TRANSPARENCY_DIR)
    if os.path.isdir(os.path.join(offline_copy, '.git')):
        online_copy = os.path.join(local_copy_dir, BINARY_TRANSPARENCY_DIR)
        push_binary_transparency(offline_copy, online_copy)


def _get_size(start_path='.'):
    """Get size of all files in a dir https://stackoverflow.com/a/1392549."""
    total_size = 0
    for root, dirs, files in os.walk(start_path):
        for f in files:
            fp = os.path.join(root, f)
            total_size += os.path.getsize(fp)
    return total_size


def update_servergitmirrors(servergitmirrors, repo_section):
    """Update repo mirrors stored in git repos.

    This is a hack to use public git repos as F-Droid repos.  It
    recreates the git repo from scratch each time, so that there is no
    history.  That keeps the size of the git repo small.  Services
    like GitHub or GitLab have a size limit of something like 1 gig.
    This git repo is only a git repo for the purpose of being hosted.
    For history, there is the archive section, and there is the binary
    transparency log.

    """
    import git
    from clint.textui import progress
    if config.get('local_copy_dir') \
       and not config.get('sync_from_local_copy_dir'):
        logging.debug(_('Offline machine, skipping git mirror generation until `fdroid deploy`'))
        return

    # right now we support only 'repo' git-mirroring
    if repo_section == 'repo':
        git_mirror_path = 'git-mirror'
        dotgit = os.path.join(git_mirror_path, '.git')
        git_fdroiddir = os.path.join(git_mirror_path, 'fdroid')
        git_repodir = os.path.join(git_fdroiddir, repo_section)
        if not os.path.isdir(git_repodir):
            os.makedirs(git_repodir)
        # github/gitlab use bare git repos, so only count the .git folder
        # test: generate giant APKs by including AndroidManifest.xml and and large
        # file from /dev/urandom, then sign it.  Then add those to the git repo.
        dotgit_size = _get_size(dotgit)
        dotgit_over_limit = dotgit_size > config['git_mirror_size_limit']
        if os.path.isdir(dotgit) and dotgit_over_limit:
            logging.warning(_('Deleting git-mirror history, repo is too big ({size} max {limit})')
                            .format(size=dotgit_size, limit=config['git_mirror_size_limit']))
            shutil.rmtree(dotgit)
        if options.no_keep_git_mirror_archive and dotgit_over_limit:
            logging.warning(_('Deleting archive, repo is too big ({size} max {limit})')
                            .format(size=dotgit_size, limit=config['git_mirror_size_limit']))
            archive_path = os.path.join(git_mirror_path, 'fdroid', 'archive')
            shutil.rmtree(archive_path, ignore_errors=True)

        # rsync is very particular about trailing slashes
        common.local_rsync(options,
                           repo_section.rstrip('/') + '/',
                           git_repodir.rstrip('/') + '/')

        # use custom SSH command if identity_file specified
        ssh_cmd = 'ssh -oBatchMode=yes'
        if options.identity_file is not None:
            ssh_cmd += ' -oIdentitiesOnly=yes -i "%s"' % options.identity_file
        elif 'identity_file' in config:
            ssh_cmd += ' -oIdentitiesOnly=yes -i "%s"' % config['identity_file']

        repo = git.Repo.init(git_mirror_path, initial_branch=GIT_BRANCH)

        enabled_remotes = []
        for remote_url in servergitmirrors:
            name = REMOTE_HOSTNAME_REGEX.sub(r'\1', remote_url)
            enabled_remotes.append(name)
            r = git.remote.Remote(repo, name)
            if r in repo.remotes:
                r = repo.remote(name)
                if 'set_url' in dir(r):  # force remote URL if using GitPython 2.x
                    r.set_url(remote_url)
            else:
                repo.create_remote(name, remote_url)
            logging.info('Mirroring to: ' + remote_url)

        # sadly index.add don't allow the --all parameter
        logging.debug('Adding all files to git mirror')
        repo.git.add(all=True)
        logging.debug('Committing all files into git mirror')
        repo.index.commit("fdroidserver git-mirror")

        if options.verbose:
            progressbar = progress.Bar()

            class MyProgressPrinter(git.RemoteProgress):
                def update(self, op_code, current, maximum=None, message=None):
                    if isinstance(maximum, float):
                        progressbar.show(current, maximum)
            progress = MyProgressPrinter()
        else:
            progress = None

        # only deploy to GitLab Artifacts if too big for GitLab Pages
        if common.get_dir_size(git_fdroiddir) <= common.GITLAB_COM_PAGES_MAX_SIZE:
            gitlab_ci_job_name = 'pages'
        else:
            gitlab_ci_job_name = 'GitLab Artifacts'
            logging.warning(
                _(
                    'Skipping GitLab Pages mirror because the repo is too large (>%.2fGB)!'
                )
                % (common.GITLAB_COM_PAGES_MAX_SIZE / 1000000000)
            )

        # push for every remote. This will overwrite the git history
        for remote in repo.remotes:
            if remote.name not in enabled_remotes:
                repo.delete_remote(remote)
                continue
            if remote.name == 'gitlab':
                logging.debug('Writing .gitlab-ci.yml to deploy to GitLab Pages')
                with open(os.path.join(git_mirror_path, ".gitlab-ci.yml"), "wt") as fp:
                    yaml.dump(
                        {
                            gitlab_ci_job_name: {
                                'script': [
                                    'mkdir .public',
                                    'cp -r * .public/',
                                    'mv .public public',
                                ],
                                'artifacts': {'paths': ['public']},
                                'variables': {'GIT_DEPTH': 1},
                            }
                        },
                        fp,
                        default_flow_style=False,
                    )

                repo.git.add(all=True)
                repo.index.commit("fdroidserver git-mirror: Deploy to GitLab Pages")

            logging.debug(_('Pushing to {url}').format(url=remote.url))
            with repo.git.custom_environment(GIT_SSH_COMMAND=ssh_cmd):
                pushinfos = remote.push(
                    GIT_BRANCH, force=True, set_upstream=True, progress=progress
                )
                for pushinfo in pushinfos:
                    if pushinfo.flags & (git.remote.PushInfo.ERROR
                                         | git.remote.PushInfo.REJECTED
                                         | git.remote.PushInfo.REMOTE_FAILURE
                                         | git.remote.PushInfo.REMOTE_REJECTED):
                        # Show potentially useful messages from git remote
                        for line in progress.other_lines:
                            if line.startswith('remote:'):
                                logging.debug(line)
                        raise FDroidException(remote.url + ' push failed: ' + str(pushinfo.flags)
                                              + ' ' + pushinfo.summary)
                    else:
                        logging.debug(remote.url + ': ' + pushinfo.summary)

        if progress:
            progressbar.done()


def upload_to_android_observatory(repo_section):
    import requests
    requests  # stop unused import warning

    if options.verbose:
        logging.getLogger("requests").setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)
    else:
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    if repo_section == 'repo':
        for f in sorted(glob.glob(os.path.join(repo_section, '*.apk'))):
            upload_apk_to_android_observatory(f)


def upload_apk_to_android_observatory(path):
    # depend on requests and lxml only if users enable AO
    import requests
    from . import net
    from lxml.html import fromstring

    apkfilename = os.path.basename(path)
    r = requests.post('https://androidobservatory.org/',
                      data={'q': common.sha256sum(path), 'searchby': 'hash'},
                      headers=net.HEADERS, timeout=300)
    if r.status_code == 200:
        # from now on XPath will be used to retrieve the message in the HTML
        # androidobservatory doesn't have a nice API to talk with
        # so we must scrape the page content
        tree = fromstring(r.text)

        href = None
        for element in tree.xpath("//html/body/div/div/table/tbody/tr/td/a"):
            a = element.attrib.get('href')
            if a:
                m = re.match(r'^/app/[0-9A-F]{40}$', a)
                if m:
                    href = m.group()

        page = 'https://androidobservatory.org'
        if href:
            message = (_('Found {apkfilename} at {url}')
                       .format(apkfilename=apkfilename, url=(page + href)))
            logging.debug(message)
            return

    # upload the file with a post request
    logging.info(_('Uploading {apkfilename} to androidobservatory.org')
                 .format(apkfilename=apkfilename))
    r = requests.post('https://androidobservatory.org/upload',
                      files={'apk': (apkfilename, open(path, 'rb'))},
                      headers=net.HEADERS,
                      allow_redirects=False, timeout=300)


def upload_to_virustotal(repo_section, virustotal_apikey):
    import requests
    requests  # stop unused import warning

    if repo_section == 'repo':
        if not os.path.exists('virustotal'):
            os.mkdir('virustotal')

        if os.path.exists(os.path.join(repo_section, 'index-v1.json')):
            with open(os.path.join(repo_section, 'index-v1.json')) as fp:
                data = json.load(fp)
        else:
            data, _ignored, _ignored = index.get_index_from_jar(os.path.join(repo_section, 'index-v1.jar'))

        for packageName, packages in data['packages'].items():
            for package in packages:
                upload_apk_to_virustotal(virustotal_apikey, **package)


def upload_apk_to_virustotal(virustotal_apikey, packageName, apkName, hash,
                             versionCode, **kwargs):
    import requests

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    outputfilename = os.path.join('virustotal',
                                  packageName + '_' + str(versionCode)
                                  + '_' + hash + '.json')
    if os.path.exists(outputfilename):
        logging.debug(apkName + ' results are in ' + outputfilename)
        return outputfilename
    repofilename = os.path.join('repo', apkName)
    logging.info('Checking if ' + repofilename + ' is on virustotal')

    headers = {
        "User-Agent": "F-Droid"
    }
    if 'headers' in kwargs:
        for k, v in kwargs['headers'].items():
            headers[k] = v

    data = {
        'apikey': virustotal_apikey,
        'resource': hash,
    }
    needs_file_upload = False
    while True:
        r = requests.get('https://www.virustotal.com/vtapi/v2/file/report?'
                         + urllib.parse.urlencode(data), headers=headers, timeout=300)
        if r.status_code == 200:
            response = r.json()
            if response['response_code'] == 0:
                needs_file_upload = True
            else:
                response['filename'] = apkName
                response['packageName'] = packageName
                response['versionCode'] = versionCode
                if kwargs.get('versionName'):
                    response['versionName'] = kwargs.get('versionName')
                with open(outputfilename, 'w') as fp:
                    json.dump(response, fp, indent=2, sort_keys=True)

            if response.get('positives', 0) > 0:
                logging.warning(repofilename + ' has been flagged by virustotal '
                                + str(response['positives']) + ' times:'
                                + '\n\t' + response['permalink'])
            break
        if r.status_code == 204:
            logging.warning(_('virustotal.com is rate limiting, waiting to retry...'))
            time.sleep(30)  # wait for public API rate limiting

    upload_url = None
    if needs_file_upload:
        manual_url = 'https://www.virustotal.com/'
        size = os.path.getsize(repofilename)
        if size > 200000000:
            # VirusTotal API 200MB hard limit
            logging.error(_('{path} more than 200MB, manually upload: {url}')
                          .format(path=repofilename, url=manual_url))
        elif size > 32000000:
            # VirusTotal API requires fetching a URL to upload bigger files
            r = requests.get('https://www.virustotal.com/vtapi/v2/file/scan/upload_url?'
                             + urllib.parse.urlencode(data), headers=headers, timeout=300)
            if r.status_code == 200:
                upload_url = r.json().get('upload_url')
            elif r.status_code == 403:
                logging.error(_('VirusTotal API key cannot upload files larger than 32MB, '
                                + 'use {url} to upload {path}.')
                              .format(path=repofilename, url=manual_url))
            else:
                r.raise_for_status()
        else:
            upload_url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    if upload_url:
        logging.info(_('Uploading {apkfilename} to virustotal')
                     .format(apkfilename=repofilename))
        files = {
            'file': (apkName, open(repofilename, 'rb'))
        }
        r = requests.post(upload_url, data=data, headers=headers, files=files, timeout=300)
        logging.debug(_('If this upload fails, try manually uploading to {url}')
                      .format(url=manual_url))
        r.raise_for_status()
        response = r.json()
        logging.info(response['verbose_msg'] + " " + response['permalink'])

    return outputfilename


def push_binary_transparency(git_repo_path, git_remote):
    """Push the binary transparency git repo to the specifed remote.

    If the remote is a local directory, make sure it exists, and is a
    git repo.  This is used to move this git repo from an offline
    machine onto a flash drive, then onto the online machine. Also,
    this pulls because pushing to a non-bare git repo is error prone.

    This is also used in offline signing setups, where it then also
    creates a "local copy dir" git repo that serves to shuttle the git
    data from the offline machine to the online machine.  In that
    case, git_remote is a dir on the local file system, e.g. a thumb
    drive.

    """
    import git

    logging.info(_('Pushing binary transparency log to {url}')
                 .format(url=git_remote))

    if os.path.isdir(os.path.dirname(git_remote)):
        # from offline machine to thumbdrive
        remote_path = os.path.abspath(git_repo_path)
        if not os.path.isdir(os.path.join(git_remote, '.git')):
            os.makedirs(git_remote, exist_ok=True)
            thumbdriverepo = git.Repo.init(git_remote, initial_branch=GIT_BRANCH)
            local = thumbdriverepo.create_remote('local', remote_path)
        else:
            thumbdriverepo = git.Repo(git_remote)
            local = git.remote.Remote(thumbdriverepo, 'local')
            if local in thumbdriverepo.remotes:
                local = thumbdriverepo.remote('local')
                if 'set_url' in dir(local):  # force remote URL if using GitPython 2.x
                    local.set_url(remote_path)
            else:
                local = thumbdriverepo.create_remote('local', remote_path)
        local.pull(GIT_BRANCH)
    else:
        # from online machine to remote on a server on the internet
        gitrepo = git.Repo(git_repo_path)
        origin = git.remote.Remote(gitrepo, 'origin')
        if origin in gitrepo.remotes:
            origin = gitrepo.remote('origin')
            if 'set_url' in dir(origin):  # added in GitPython 2.x
                origin.set_url(git_remote)
        else:
            origin = gitrepo.create_remote('origin', git_remote)
        origin.push(GIT_BRANCH)


def main():
    global config, options

    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("-i", "--identity-file", default=None,
                        help=_("Specify an identity file to provide to SSH for rsyncing"))
    parser.add_argument("--local-copy-dir", default=None,
                        help=_("Specify a local folder to sync the repo to"))
    parser.add_argument("--no-checksum", action="store_true", default=False,
                        help=_("Don't use rsync checksums"))
    parser.add_argument("--no-keep-git-mirror-archive", action="store_true", default=False,
                        help=_("If a git mirror gets to big, allow the archive to be deleted"))
    options = parser.parse_args()
    config = common.read_config(options)

    if config.get('nonstandardwebroot') is True:
        standardwebroot = False
    else:
        standardwebroot = True

    for serverwebroot in config.get('serverwebroot', []):
        # this supports both an ssh host:path and just a path
        s = serverwebroot.rstrip('/').split(':')
        if len(s) == 1:
            fdroiddir = s[0]
        elif len(s) == 2:
            host, fdroiddir = s
        else:
            logging.error(_('Malformed serverwebroot line:') + ' ' + serverwebroot)
            sys.exit(1)
        repobase = os.path.basename(fdroiddir)
        if standardwebroot and repobase != 'fdroid':
            logging.error('serverwebroot path does not end with "fdroid", '
                          + 'perhaps you meant one of these:\n\t'
                          + serverwebroot.rstrip('/') + '/fdroid\n\t'
                          + serverwebroot.rstrip('/').rstrip(repobase) + 'fdroid')
            sys.exit(1)

    if options.local_copy_dir is not None:
        local_copy_dir = options.local_copy_dir
    elif config.get('local_copy_dir'):
        local_copy_dir = config['local_copy_dir']
    else:
        local_copy_dir = None
    if local_copy_dir is not None:
        fdroiddir = local_copy_dir.rstrip('/')
        if os.path.exists(fdroiddir) and not os.path.isdir(fdroiddir):
            logging.error(_('local_copy_dir must be directory, not a file!'))
            sys.exit(1)
        if not os.path.exists(os.path.dirname(fdroiddir)):
            logging.error(_('The root dir for local_copy_dir "{path}" does not exist!')
                          .format(path=os.path.dirname(fdroiddir)))
            sys.exit(1)
        if not os.path.isabs(fdroiddir):
            logging.error(_('local_copy_dir must be an absolute path!'))
            sys.exit(1)
        repobase = os.path.basename(fdroiddir)
        if standardwebroot and repobase != 'fdroid':
            logging.error(_('local_copy_dir does not end with "fdroid", '
                            + 'perhaps you meant: "{path}"')
                          .format(path=fdroiddir + '/fdroid'))
            sys.exit(1)
        if local_copy_dir[-1] != '/':
            local_copy_dir += '/'
        local_copy_dir = local_copy_dir.replace('//', '/')
        if not os.path.exists(fdroiddir):
            os.mkdir(fdroiddir)

    if not config.get('awsbucket') \
            and not config.get('serverwebroot') \
            and not config.get('servergitmirrors') \
            and not config.get('androidobservatory') \
            and not config.get('binary_transparency_remote') \
            and not config.get('virustotal_apikey') \
            and local_copy_dir is None:
        logging.warning(_('No option set! Edit your config.yml to set at least one of these:')
                        + '\nserverwebroot, servergitmirrors, local_copy_dir, awsbucket, '
                        + 'virustotal_apikey, androidobservatory, or binary_transparency_remote')
        sys.exit(1)

    repo_sections = ['repo']
    if config['archive_older'] != 0:
        repo_sections.append('archive')
        if not os.path.exists('archive'):
            os.mkdir('archive')
    if config['per_app_repos']:
        repo_sections += common.get_per_app_repos()

    if os.path.isdir('unsigned') or (local_copy_dir is not None
                                     and os.path.isdir(os.path.join(local_copy_dir, 'unsigned'))):
        repo_sections.append('unsigned')

    for repo_section in repo_sections:
        if local_copy_dir is not None:
            if config['sync_from_local_copy_dir']:
                sync_from_localcopy(repo_section, local_copy_dir)
            else:
                update_localcopy(repo_section, local_copy_dir)
        for serverwebroot in config.get('serverwebroot', []):
            update_serverwebroot(serverwebroot, repo_section)
        if config.get('servergitmirrors', []):
            # update_servergitmirrors will take care of multiple mirrors so don't need a foreach
            servergitmirrors = config.get('servergitmirrors', [])
            update_servergitmirrors(servergitmirrors, repo_section)
        if config.get('awsbucket'):
            update_awsbucket(repo_section)
        if config.get('androidobservatory'):
            upload_to_android_observatory(repo_section)
        if config.get('virustotal_apikey'):
            upload_to_virustotal(repo_section, config.get('virustotal_apikey'))

    binary_transparency_remote = config.get('binary_transparency_remote')
    if binary_transparency_remote:
        push_binary_transparency(BINARY_TRANSPARENCY_DIR,
                                 binary_transparency_remote)

    common.write_status_json(common.setup_status_output(start_timestamp))
    sys.exit(0)


if __name__ == "__main__":
    main()
