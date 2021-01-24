#!/usr/bin/env python3

import git
import gitlab
import os
import re
import requests
from bs4 import BeautifulSoup
from distutils.version import LooseVersion

checksums = None
versions = dict()

import json
with open('checksums.json') as fp:
    checksums = json.load(fp)

while not checksums:
   r = requests.get('https://gitlab.com/fdroid/gradle-transparency-log/-/raw/master/checksums.json')
   if r.status_code == 200:
       checksums = r.json()

gradle_bin_pat = re.compile(r'gradle-([0-9][0-9.]+[0-9])-bin.zip')
for url, d in checksums.items():
    m = gradle_bin_pat.search(url)
    if m:
        versions[m.group(1)] = d[0]['sha256']

errors = 0
makebuildserver = os.path.join(os.path.dirname(__file__), os.pardir, 'makebuildserver')
with open(makebuildserver) as fp:
    makebuildserver_current = fp.read()
to_compile = re.search(r'CACHE_FILES = [^\]]+\]', makebuildserver_current).group()
code = compile(to_compile, makebuildserver, 'exec')
config = {}
exec(code, None, config)  # nosec this is just a CI script
makebuildserver_versions = []
version_pat = re.compile(r'[0-9]+(\.[0-9]+)+')
for url, checksum in config['CACHE_FILES']:
    if 'gradle.org' in url:
        m = version_pat.search(url.split('/')[-1])
        if m:
            makebuildserver_versions.append(m.group())
            if checksum != versions[m.group()]:
                print('ERROR: checksum mismatch:', checksum, versions[m.group()])
                errors += 1
if errors:
    exit(errors)

# error if makebuildserver is missing the latest version
for version in sorted(versions.keys()):
    if version not in makebuildserver_versions \
       and LooseVersion(version) > LooseVersion(sorted(makebuildserver_versions)[-1]):
        add_before = """    ('https://dl.google.com/android/ndk/android-ndk-r10e-linux-x86_64.bin',"""
        new = to_compile.replace(
            add_before,
            "    ('https://services.gradle.org/distributions/gradle-" + version + "-bin.zip',\n"
            "     '" + versions[version] + "'),\n" + add_before
        )
        makebuildserver_current = makebuildserver_current.replace(to_compile, new)

with open('makebuildserver', 'w') as fp:
    fp.write(makebuildserver_current)

# write out update to gradlew-fdroid
with open('gradlew-fdroid') as fp:
    gradlew_fdroid = fp.read()
current = ''
get_sha_pat = re.compile(r""" +'([0-9][0-9.]+[0-9])'\)\s+echo '([0-9a-f]{64})' ;;\n""")
for m in get_sha_pat.finditer(gradlew_fdroid):
    current += m.group()
new = ''
for version in sorted(versions.keys(), key=LooseVersion):
    sha256 = versions[version]
    spaces = ''
    for i in range(6 - len(version)):
        spaces += ' '
    new += """        '%s')%s echo '%s' ;;\n""" % (version, spaces, sha256)
gradlew_fdroid = gradlew_fdroid.replace(current, new)
plugin_v = ' '.join(sorted(versions.keys(), key=LooseVersion, reverse=True))
plugin_v_pat = re.compile(r'\nplugin_v=\(([0-9. ]+)\)')
with open('gradlew-fdroid', 'w') as fp:
    fp.write(plugin_v_pat.sub('\nplugin_v=(%s)' % plugin_v, gradlew_fdroid))

git_repo = git.repo.Repo('.')
modified = git_repo.git().ls_files(modified=True).split()
if (git_repo.is_dirty()
    and ('gradlew-fdroid' in modified or 'makebuildserver' in modified)):
    branch = git_repo.create_head(os.path.basename(__file__), force=True)
    branch.checkout()
    git_repo.index.add(['gradlew-fdroid', 'makebuildserver'])
    author = git.Actor('fdroid-bot', 'fdroid-bot@f-droid.org')
    git_repo.index.commit('gradle v' + version, author=author)
    url = ('git@%s:fdroid-bot/%s.git'
           % (os.getenv('CI_SERVER_HOST'), os.getenv('CI_PROJECT_NAME')))
    try:
        remote = git_repo.create_remote('fdroid-bot', url)
    except git.exc.GitCommandError:
        remote = git.remote.Remote(git_repo, 'fdroid-bot')
        remote.set_url(url)
    remote.push(force=True)
