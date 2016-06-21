#!/usr/bin/env python3
#
# update.py - part of the FDroid server tools
# Copyright (C) 2010-2015, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
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
import os
import shutil
import glob
import re
import socket
import zipfile
import hashlib
import pickle
import urllib.parse
from datetime import datetime, timedelta
from xml.dom.minidom import Document
from argparse import ArgumentParser
import time
from pyasn1.error import PyAsn1Error
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2315
from binascii import hexlify, unhexlify

from PIL import Image
import logging

from . import common
from . import metadata
from .common import FDroidPopen, FDroidPopenBytes, SdkToolsPopen
from .metadata import MetaDataException

METADATA_VERSION = 16

screen_densities = ['640', '480', '320', '240', '160', '120']

all_screen_densities = ['0'] + screen_densities


def dpi_to_px(density):
    return (int(density) * 48) / 160


def px_to_dpi(px):
    return (int(px) * 160) / 48


def get_icon_dir(repodir, density):
    if density == '0':
        return os.path.join(repodir, "icons")
    return os.path.join(repodir, "icons-%s" % density)


def get_icon_dirs(repodir):
    for density in screen_densities:
        yield get_icon_dir(repodir, density)


def get_all_icon_dirs(repodir):
    for density in all_screen_densities:
        yield get_icon_dir(repodir, density)


def update_wiki(apps, sortedids, apks):
    """Update the wiki

    :param apps: fully populated list of all applications
    :param apks: all apks, except...
    """
    logging.info("Updating wiki")
    wikicat = 'Apps'
    wikiredircat = 'App Redirects'
    import mwclient
    site = mwclient.Site((config['wiki_protocol'], config['wiki_server']),
                         path=config['wiki_path'])
    site.login(config['wiki_user'], config['wiki_password'])
    generated_pages = {}
    generated_redirects = {}

    for appid in sortedids:
        app = apps[appid]

        wikidata = ''
        if app.Disabled:
            wikidata += '{{Disabled|' + app.Disabled + '}}\n'
        if app.AntiFeatures:
            for af in app.AntiFeatures:
                wikidata += '{{AntiFeature|' + af + '}}\n'
        if app.RequiresRoot:
            requiresroot = 'Yes'
        else:
            requiresroot = 'No'
        wikidata += '{{App|id=%s|name=%s|added=%s|lastupdated=%s|source=%s|tracker=%s|web=%s|changelog=%s|donate=%s|flattr=%s|bitcoin=%s|litecoin=%s|license=%s|root=%s|author=%s|email=%s}}\n' % (
            appid,
            app.Name,
            time.strftime('%Y-%m-%d', app.added) if app.added else '',
            time.strftime('%Y-%m-%d', app.lastupdated) if app.lastupdated else '',
            app.SourceCode,
            app.IssueTracker,
            app.WebSite,
            app.Changelog,
            app.Donate,
            app.FlattrID,
            app.Bitcoin,
            app.Litecoin,
            app.License,
            requiresroot,
            app.AuthorName,
            app.AuthorEmail)

        if app.Provides:
            wikidata += "This app provides: %s" % ', '.join(app.Summary.split(','))

        wikidata += app.Summary
        wikidata += " - [https://f-droid.org/repository/browse/?fdid=" + appid + " view in repository]\n\n"

        wikidata += "=Description=\n"
        wikidata += metadata.description_wiki(app.Description) + "\n"

        wikidata += "=Maintainer Notes=\n"
        if app.MaintainerNotes:
            wikidata += metadata.description_wiki(app.MaintainerNotes) + "\n"
        wikidata += "\nMetadata: [https://gitlab.com/fdroid/fdroiddata/blob/master/metadata/{0}.txt current] [https://gitlab.com/fdroid/fdroiddata/commits/master/metadata/{0}.txt history]\n".format(appid)

        # Get a list of all packages for this application...
        apklist = []
        gotcurrentver = False
        cantupdate = False
        buildfails = False
        for apk in apks:
            if apk['id'] == appid:
                if str(apk['versioncode']) == app.CurrentVersionCode:
                    gotcurrentver = True
                apklist.append(apk)
        # Include ones we can't build, as a special case...
        for build in app.builds:
            if build.disable:
                if build.vercode == app.CurrentVersionCode:
                    cantupdate = True
                # TODO: Nasty: vercode is a string in the build, and an int elsewhere
                apklist.append({'versioncode': int(build.vercode),
                                'version': build.version,
                                'buildproblem': "The build for this version was manually disabled. Reason: {0}".format(build.disable),
                                })
            else:
                builtit = False
                for apk in apklist:
                    if apk['versioncode'] == int(build.vercode):
                        builtit = True
                        break
                if not builtit:
                    buildfails = True
                    apklist.append({'versioncode': int(build.vercode),
                                    'version': build.version,
                                    'buildproblem': "The build for this version appears to have failed. Check the [[{0}/lastbuild_{1}|build log]].".format(appid, build.vercode),
                                    })
        if app.CurrentVersionCode == '0':
            cantupdate = True
        # Sort with most recent first...
        apklist = sorted(apklist, key=lambda apk: apk['versioncode'], reverse=True)

        wikidata += "=Versions=\n"
        if len(apklist) == 0:
            wikidata += "We currently have no versions of this app available."
        elif not gotcurrentver:
            wikidata += "We don't have the current version of this app."
        else:
            wikidata += "We have the current version of this app."
        wikidata += " (Check mode: " + app.UpdateCheckMode + ") "
        wikidata += " (Auto-update mode: " + app.AutoUpdateMode + ")\n\n"
        if len(app.NoSourceSince) > 0:
            wikidata += "This application has partially or entirely been missing source code since version " + app.NoSourceSince + ".\n\n"
        if len(app.CurrentVersion) > 0:
            wikidata += "The current (recommended) version is " + app.CurrentVersion
            wikidata += " (version code " + app.CurrentVersionCode + ").\n\n"
        validapks = 0
        for apk in apklist:
            wikidata += "==" + apk['version'] + "==\n"

            if 'buildproblem' in apk:
                wikidata += "We can't build this version: " + apk['buildproblem'] + "\n\n"
            else:
                validapks += 1
                wikidata += "This version is built and signed by "
                if 'srcname' in apk:
                    wikidata += "F-Droid, and guaranteed to correspond to the source tarball published with it.\n\n"
                else:
                    wikidata += "the original developer.\n\n"
            wikidata += "Version code: " + str(apk['versioncode']) + '\n'

        wikidata += '\n[[Category:' + wikicat + ']]\n'
        if len(app.NoSourceSince) > 0:
            wikidata += '\n[[Category:Apps missing source code]]\n'
        if validapks == 0 and not app.Disabled:
            wikidata += '\n[[Category:Apps with no packages]]\n'
        if cantupdate and not app.Disabled:
            wikidata += "\n[[Category:Apps we cannot update]]\n"
        if buildfails and not app.Disabled:
            wikidata += "\n[[Category:Apps with failing builds]]\n"
        elif not gotcurrentver and not cantupdate and not app.Disabled and app.UpdateCheckMode != "Static":
            wikidata += '\n[[Category:Apps to Update]]\n'
        if app.Disabled:
            wikidata += '\n[[Category:Apps that are disabled]]\n'
        if app.UpdateCheckMode == 'None' and not app.Disabled:
            wikidata += '\n[[Category:Apps with no update check]]\n'
        for appcat in app.Categories:
            wikidata += '\n[[Category:{0}]]\n'.format(appcat)

        # We can't have underscores in the page name, even if they're in
        # the package ID, because MediaWiki messes with them...
        pagename = appid.replace('_', ' ')

        # Drop a trailing newline, because mediawiki is going to drop it anyway
        # and it we don't we'll think the page has changed when it hasn't...
        if wikidata.endswith('\n'):
            wikidata = wikidata[:-1]

        generated_pages[pagename] = wikidata

        # Make a redirect from the name to the ID too, unless there's
        # already an existing page with the name and it isn't a redirect.
        noclobber = False
        apppagename = app.Name.replace('_', ' ')
        apppagename = apppagename.replace('{', '')
        apppagename = apppagename.replace('}', ' ')
        apppagename = apppagename.replace(':', ' ')
        # Drop double spaces caused mostly by replacing ':' above
        apppagename = apppagename.replace('  ', ' ')
        for expagename in site.allpages(prefix=apppagename,
                                        filterredir='nonredirects',
                                        generator=False):
            if expagename == apppagename:
                noclobber = True
        # Another reason not to make the redirect page is if the app name
        # is the same as it's ID, because that will overwrite the real page
        # with an redirect to itself! (Although it seems like an odd
        # scenario this happens a lot, e.g. where there is metadata but no
        # builds or binaries to extract a name from.
        if apppagename == pagename:
            noclobber = True
        if not noclobber:
            generated_redirects[apppagename] = "#REDIRECT [[" + pagename + "]]\n[[Category:" + wikiredircat + "]]"

    for tcat, genp in [(wikicat, generated_pages),
                       (wikiredircat, generated_redirects)]:
        catpages = site.Pages['Category:' + tcat]
        existingpages = []
        for page in catpages:
            existingpages.append(page.name)
            if page.name in genp:
                pagetxt = page.edit()
                if pagetxt != genp[page.name]:
                    logging.debug("Updating modified page " + page.name)
                    page.save(genp[page.name], summary='Auto-updated')
                else:
                    logging.debug("Page " + page.name + " is unchanged")
            else:
                logging.warn("Deleting page " + page.name)
                page.delete('No longer published')
        for pagename, text in genp.items():
            logging.debug("Checking " + pagename)
            if pagename not in existingpages:
                logging.debug("Creating page " + pagename)
                try:
                    newpage = site.Pages[pagename]
                    newpage.save(text, summary='Auto-created')
                except:
                    logging.error("...FAILED to create page '{0}'".format(pagename))

    # Purge server cache to ensure counts are up to date
    site.pages['Repository Maintenance'].purge()


def delete_disabled_builds(apps, apkcache, repodirs):
    """Delete disabled build outputs.

    :param apps: list of all applications, as per metadata.read_metadata
    :param apkcache: current apk cache information
    :param repodirs: the repo directories to process
    """
    for appid, app in apps.items():
        for build in app.builds:
            if not build.disable:
                continue
            apkfilename = appid + '_' + str(build.vercode) + '.apk'
            iconfilename = "%s.%s.png" % (
                appid,
                build.vercode)
            for repodir in repodirs:
                files = [
                    os.path.join(repodir, apkfilename),
                    os.path.join(repodir, apkfilename + '.asc'),
                    os.path.join(repodir, apkfilename[:-4] + "_src.tar.gz"),
                ]
                for density in all_screen_densities:
                    repo_dir = get_icon_dir(repodir, density)
                    files.append(os.path.join(repo_dir, iconfilename))

                for f in files:
                    if os.path.exists(f):
                        logging.info("Deleting disabled build output " + f)
                        os.remove(f)
            if apkfilename in apkcache:
                del apkcache[apkfilename]


def resize_icon(iconpath, density):

    if not os.path.isfile(iconpath):
        return

    fp = None
    try:
        fp = open(iconpath, 'rb')
        im = Image.open(fp)
        size = dpi_to_px(density)

        if any(length > size for length in im.size):
            oldsize = im.size
            im.thumbnail((size, size), Image.ANTIALIAS)
            logging.debug("%s was too large at %s - new size is %s" % (
                iconpath, oldsize, im.size))
            im.save(iconpath, "PNG")

    except Exception as e:
        logging.error("Failed resizing {0} - {1}".format(iconpath, e))

    finally:
        if fp:
            fp.close()


def resize_all_icons(repodirs):
    """Resize all icons that exceed the max size

    :param repodirs: the repo directories to process
    """
    for repodir in repodirs:
        for density in screen_densities:
            icon_dir = get_icon_dir(repodir, density)
            icon_glob = os.path.join(icon_dir, '*.png')
            for iconpath in glob.glob(icon_glob):
                resize_icon(iconpath, density)


# A signature block file with a .DSA, .RSA, or .EC extension
cert_path_regex = re.compile(r'^META-INF/.*\.(DSA|EC|RSA)$')


def getsig(apkpath):
    """ Get the signing certificate of an apk. To get the same md5 has that
    Android gets, we encode the .RSA certificate in a specific format and pass
    it hex-encoded to the md5 digest algorithm.

    :param apkpath: path to the apk
    :returns: A string containing the md5 of the signature of the apk or None
              if an error occurred.
    """

    cert = None

    # verify the jar signature is correct
    args = [config['jarsigner'], '-verify', apkpath]
    p = FDroidPopen(args)
    if p.returncode != 0:
        logging.critical(apkpath + " has a bad signature!")
        return None

    with zipfile.ZipFile(apkpath, 'r') as apk:

        certs = [n for n in apk.namelist() if cert_path_regex.match(n)]

        if len(certs) < 1:
            logging.error("Found no signing certificates on %s" % apkpath)
            return None
        if len(certs) > 1:
            logging.error("Found multiple signing certificates on %s" % apkpath)
            return None

        cert = apk.read(certs[0])

    content = decoder.decode(cert, asn1Spec=rfc2315.ContentInfo())[0]
    if content.getComponentByName('contentType') != rfc2315.signedData:
        logging.error("Unexpected format.")
        return None

    content = decoder.decode(content.getComponentByName('content'),
                             asn1Spec=rfc2315.SignedData())[0]
    try:
        certificates = content.getComponentByName('certificates')
    except PyAsn1Error:
        logging.error("Certificates not found.")
        return None

    cert_encoded = encoder.encode(certificates)[4:]

    return hashlib.md5(hexlify(cert_encoded)).hexdigest()


def scan_apks(apps, apkcache, repodir, knownapks, use_date_from_apk=False):
    """Scan the apks in the given repo directory.

    This also extracts the icons.

    :param apps: list of all applications, as per metadata.read_metadata
    :param apkcache: current apk cache information
    :param repodir: repo directory to scan
    :param knownapks: known apks info
    :param use_date_from_apk: use date from APK (instead of current date)
                              for newly added APKs
    :returns: (apks, cachechanged) where apks is a list of apk information,
              and cachechanged is True if the apkcache got changed.
    """

    cachechanged = False

    for icon_dir in get_all_icon_dirs(repodir):
        if os.path.exists(icon_dir):
            if options.clean:
                shutil.rmtree(icon_dir)
                os.makedirs(icon_dir)
        else:
            os.makedirs(icon_dir)

    apks = []
    name_pat = re.compile(".*name='([a-zA-Z0-9._]*)'.*")
    vercode_pat = re.compile(".*versionCode='([0-9]*)'.*")
    vername_pat = re.compile(".*versionName='([^']*)'.*")
    label_pat = re.compile(".*label='(.*?)'(\n| [a-z]*?=).*")
    icon_pat = re.compile(".*application-icon-([0-9]+):'([^']+?)'.*")
    icon_pat_nodpi = re.compile(".*icon='([^']+?)'.*")
    sdkversion_pat = re.compile(".*'([0-9]*)'.*")
    string_pat = re.compile(".*'([^']*)'.*")
    for apkfile in glob.glob(os.path.join(repodir, '*.apk')):

        apkfilename = apkfile[len(repodir) + 1:]
        if ' ' in apkfilename:
            logging.critical("Spaces in filenames are not allowed.")
            sys.exit(1)

        # Calculate the sha256...
        sha = hashlib.sha256()
        with open(apkfile, 'rb') as f:
            while True:
                t = f.read(16384)
                if len(t) == 0:
                    break
                sha.update(t)
            shasum = sha.hexdigest()

        usecache = False
        if apkfilename in apkcache:
            apk = apkcache[apkfilename]
            if apk['sha256'] == shasum:
                logging.debug("Reading " + apkfilename + " from cache")
                usecache = True
            else:
                logging.debug("Ignoring stale cache data for " + apkfilename)

        if not usecache:
            logging.debug("Processing " + apkfilename)
            apk = {}
            apk['apkname'] = apkfilename
            apk['sha256'] = shasum
            srcfilename = apkfilename[:-4] + "_src.tar.gz"
            if os.path.exists(os.path.join(repodir, srcfilename)):
                apk['srcname'] = srcfilename
            apk['size'] = os.path.getsize(apkfile)
            apk['permissions'] = set()
            apk['features'] = set()
            apk['icons_src'] = {}
            apk['icons'] = {}
            p = SdkToolsPopen(['aapt', 'dump', 'badging', apkfile], output=False)
            if p.returncode != 0:
                if options.delete_unknown:
                    if os.path.exists(apkfile):
                        logging.error("Failed to get apk information, deleting " + apkfile)
                        os.remove(apkfile)
                    else:
                        logging.error("Could not find {0} to remove it".format(apkfile))
                else:
                    logging.error("Failed to get apk information, skipping " + apkfile)
                continue
            for line in p.output.splitlines():
                if line.startswith("package:"):
                    try:
                        apk['id'] = re.match(name_pat, line).group(1)
                        apk['versioncode'] = int(re.match(vercode_pat, line).group(1))
                        apk['version'] = re.match(vername_pat, line).group(1)
                    except Exception as e:
                        logging.error("Package matching failed: " + str(e))
                        logging.info("Line was: " + line)
                        sys.exit(1)
                elif line.startswith("application:"):
                    apk['name'] = re.match(label_pat, line).group(1)
                    # Keep path to non-dpi icon in case we need it
                    match = re.match(icon_pat_nodpi, line)
                    if match:
                        apk['icons_src']['-1'] = match.group(1)
                elif line.startswith("launchable-activity:"):
                    # Only use launchable-activity as fallback to application
                    if not apk['name']:
                        apk['name'] = re.match(label_pat, line).group(1)
                    if '-1' not in apk['icons_src']:
                        match = re.match(icon_pat_nodpi, line)
                        if match:
                            apk['icons_src']['-1'] = match.group(1)
                elif line.startswith("application-icon-"):
                    match = re.match(icon_pat, line)
                    if match:
                        density = match.group(1)
                        path = match.group(2)
                        apk['icons_src'][density] = path
                elif line.startswith("sdkVersion:"):
                    m = re.match(sdkversion_pat, line)
                    if m is None:
                        logging.error(line.replace('sdkVersion:', '')
                                      + ' is not a valid minSdkVersion!')
                    else:
                        apk['minSdkVersion'] = m.group(1)
                        # if target not set, default to min
                        if 'targetSdkVersion' not in apk:
                            apk['targetSdkVersion'] = m.group(1)
                elif line.startswith("targetSdkVersion:"):
                    m = re.match(sdkversion_pat, line)
                    if m is None:
                        logging.error(line.replace('targetSdkVersion:', '')
                                      + ' is not a valid targetSdkVersion!')
                    else:
                        apk['targetSdkVersion'] = m.group(1)
                elif line.startswith("maxSdkVersion:"):
                    apk['maxSdkVersion'] = re.match(sdkversion_pat, line).group(1)
                elif line.startswith("native-code:"):
                    apk['nativecode'] = []
                    for arch in line[13:].split(' '):
                        apk['nativecode'].append(arch[1:-1])
                elif line.startswith("uses-permission:"):
                    perm = re.match(string_pat, line).group(1)
                    if perm.startswith("android.permission."):
                        perm = perm[19:]
                    apk['permissions'].add(perm)
                elif line.startswith("uses-feature:"):
                    perm = re.match(string_pat, line).group(1)
                    # Filter out this, it's only added with the latest SDK tools and
                    # causes problems for lots of apps.
                    if perm != "android.hardware.screen.portrait" \
                            and perm != "android.hardware.screen.landscape":
                        if perm.startswith("android.feature."):
                            perm = perm[16:]
                        apk['features'].add(perm)

            if 'minSdkVersion' not in apk:
                logging.warn("No SDK version information found in {0}".format(apkfile))
                apk['minSdkVersion'] = 1

            # Check for debuggable apks...
            if common.isApkDebuggable(apkfile, config):
                logging.warning('{0} is set to android:debuggable="true"'.format(apkfile))

            # Get the signature (or md5 of, to be precise)...
            logging.debug('Getting signature of {0}'.format(apkfile))
            apk['sig'] = getsig(os.path.join(os.getcwd(), apkfile))
            if not apk['sig']:
                logging.critical("Failed to get apk signature")
                sys.exit(1)

            apkzip = zipfile.ZipFile(apkfile, 'r')

            # if an APK has files newer than the system time, suggest updating
            # the system clock.  This is useful for offline systems, used for
            # signing, which do not have another source of clock sync info. It
            # has to be more than 24 hours newer because ZIP/APK files do not
            # store timezone info
            manifest = apkzip.getinfo('AndroidManifest.xml')
            if manifest.date_time[1] == 0:  # month can't be zero
                logging.debug('AndroidManifest.xml has no date')
            else:
                dt_obj = datetime(*manifest.date_time)
                checkdt = dt_obj - timedelta(1)
                if datetime.today() < checkdt:
                    logging.warn('System clock is older than manifest in: '
                                 + apkfilename
                                 + '\nSet clock to that time using:\n'
                                 + 'sudo date -s "' + str(dt_obj) + '"')

            iconfilename = "%s.%s.png" % (
                apk['id'],
                apk['versioncode'])

            # Extract the icon file...
            empty_densities = []
            for density in screen_densities:
                if density not in apk['icons_src']:
                    empty_densities.append(density)
                    continue
                iconsrc = apk['icons_src'][density]
                icon_dir = get_icon_dir(repodir, density)
                icondest = os.path.join(icon_dir, iconfilename)

                try:
                    with open(icondest, 'wb') as f:
                        f.write(apkzip.read(iconsrc))
                    apk['icons'][density] = iconfilename

                except:
                    logging.warn("Error retrieving icon file")
                    del apk['icons'][density]
                    del apk['icons_src'][density]
                    empty_densities.append(density)

            if '-1' in apk['icons_src']:
                iconsrc = apk['icons_src']['-1']
                iconpath = os.path.join(
                    get_icon_dir(repodir, '0'), iconfilename)
                with open(iconpath, 'wb') as f:
                    f.write(apkzip.read(iconsrc))
                try:
                    im = Image.open(iconpath)
                    dpi = px_to_dpi(im.size[0])
                    for density in screen_densities:
                        if density in apk['icons']:
                            break
                        if density == screen_densities[-1] or dpi >= int(density):
                            apk['icons'][density] = iconfilename
                            shutil.move(iconpath,
                                        os.path.join(get_icon_dir(repodir, density), iconfilename))
                            empty_densities.remove(density)
                            break
                except Exception as e:
                    logging.warn("Failed reading {0} - {1}".format(iconpath, e))

            if apk['icons']:
                apk['icon'] = iconfilename

            apkzip.close()

            # First try resizing down to not lose quality
            last_density = None
            for density in screen_densities:
                if density not in empty_densities:
                    last_density = density
                    continue
                if last_density is None:
                    continue
                logging.debug("Density %s not available, resizing down from %s"
                              % (density, last_density))

                last_iconpath = os.path.join(
                    get_icon_dir(repodir, last_density), iconfilename)
                iconpath = os.path.join(
                    get_icon_dir(repodir, density), iconfilename)
                fp = None
                try:
                    fp = open(last_iconpath, 'rb')
                    im = Image.open(fp)

                    size = dpi_to_px(density)

                    im.thumbnail((size, size), Image.ANTIALIAS)
                    im.save(iconpath, "PNG")
                    empty_densities.remove(density)
                except:
                    logging.warning("Invalid image file at %s" % last_iconpath)
                finally:
                    if fp:
                        fp.close()

            # Then just copy from the highest resolution available
            last_density = None
            for density in reversed(screen_densities):
                if density not in empty_densities:
                    last_density = density
                    continue
                if last_density is None:
                    continue
                logging.debug("Density %s not available, copying from lower density %s"
                              % (density, last_density))

                shutil.copyfile(
                    os.path.join(get_icon_dir(repodir, last_density), iconfilename),
                    os.path.join(get_icon_dir(repodir, density), iconfilename))

                empty_densities.remove(density)

            for density in screen_densities:
                icon_dir = get_icon_dir(repodir, density)
                icondest = os.path.join(icon_dir, iconfilename)
                resize_icon(icondest, density)

            # Copy from icons-mdpi to icons since mdpi is the baseline density
            baseline = os.path.join(get_icon_dir(repodir, '160'), iconfilename)
            if os.path.isfile(baseline):
                apk['icons']['0'] = iconfilename
                shutil.copyfile(baseline,
                                os.path.join(get_icon_dir(repodir, '0'), iconfilename))

            # Record in known apks, getting the added date at the same time..
            added = knownapks.recordapk(apk['apkname'], apk['id'])
            if added:
                if use_date_from_apk and manifest.date_time[1] != 0:
                    added = datetime(*manifest.date_time).timetuple()
                    logging.debug("Using date from APK")

                apk['added'] = added

            apkcache[apkfilename] = apk
            cachechanged = True

        apks.append(apk)

    return apks, cachechanged


repo_pubkey_fingerprint = None


# Generate a certificate fingerprint the same way keytool does it
# (but with slightly different formatting)
def cert_fingerprint(data):
    digest = hashlib.sha256(data).digest()
    ret = []
    ret.append(' '.join("%02X" % b for b in bytearray(digest)))
    return " ".join(ret)


def extract_pubkey():
    global repo_pubkey_fingerprint
    if 'repo_pubkey' in config:
        pubkey = unhexlify(config['repo_pubkey'])
    else:
        p = FDroidPopenBytes([config['keytool'], '-exportcert',
                              '-alias', config['repo_keyalias'],
                              '-keystore', config['keystore'],
                              '-storepass:file', config['keystorepassfile']]
                             + config['smartcardoptions'],
                             output=False, stderr_to_stdout=False)
        if p.returncode != 0 or len(p.output) < 20:
            msg = "Failed to get repo pubkey!"
            if config['keystore'] == 'NONE':
                msg += ' Is your crypto smartcard plugged in?'
            logging.critical(msg)
            sys.exit(1)
        pubkey = p.output
    repo_pubkey_fingerprint = cert_fingerprint(pubkey)
    return hexlify(pubkey)


def make_index(apps, sortedids, apks, repodir, archive, categories):
    """Make a repo index.

    :param apps: fully populated apps list
    :param apks: full populated apks list
    :param repodir: the repo directory
    :param archive: True if this is the archive repo, False if it's the
                    main one.
    :param categories: list of categories
    """

    doc = Document()

    def addElement(name, value, doc, parent):
        el = doc.createElement(name)
        el.appendChild(doc.createTextNode(value))
        parent.appendChild(el)

    def addElementNonEmpty(name, value, doc, parent):
        if not value:
            return
        addElement(name, value, doc, parent)

    def addElementCDATA(name, value, doc, parent):
        el = doc.createElement(name)
        el.appendChild(doc.createCDATASection(value))
        parent.appendChild(el)

    root = doc.createElement("fdroid")
    doc.appendChild(root)

    repoel = doc.createElement("repo")

    mirrorcheckfailed = False
    for mirror in config.get('mirrors', []):
        base = os.path.basename(urllib.parse.urlparse(mirror).path.rstrip('/'))
        if config.get('nonstandardwebroot') is not True and base != 'fdroid':
            logging.error("mirror '" + mirror + "' does not end with 'fdroid'!")
            mirrorcheckfailed = True
    if mirrorcheckfailed:
        sys.exit(1)

    if archive:
        repoel.setAttribute("name", config['archive_name'])
        if config['repo_maxage'] != 0:
            repoel.setAttribute("maxage", str(config['repo_maxage']))
        repoel.setAttribute("icon", os.path.basename(config['archive_icon']))
        repoel.setAttribute("url", config['archive_url'])
        addElement('description', config['archive_description'], doc, repoel)
        urlbasepath = os.path.basename(urllib.parse.urlparse(config['archive_url']).path)
        for mirror in config.get('mirrors', []):
            addElement('mirror', urllib.parse.urljoin(mirror, urlbasepath), doc, repoel)

    else:
        repoel.setAttribute("name", config['repo_name'])
        if config['repo_maxage'] != 0:
            repoel.setAttribute("maxage", str(config['repo_maxage']))
        repoel.setAttribute("icon", os.path.basename(config['repo_icon']))
        repoel.setAttribute("url", config['repo_url'])
        addElement('description', config['repo_description'], doc, repoel)
        urlbasepath = os.path.basename(urllib.parse.urlparse(config['repo_url']).path)
        for mirror in config.get('mirrors', []):
            addElement('mirror', urllib.parse.urljoin(mirror, urlbasepath), doc, repoel)

    repoel.setAttribute("version", str(METADATA_VERSION))
    repoel.setAttribute("timestamp", str(int(time.time())))

    nosigningkey = False
    if not options.nosign:
        if 'repo_keyalias' not in config:
            nosigningkey = True
            logging.critical("'repo_keyalias' not found in config.py!")
        if 'keystore' not in config:
            nosigningkey = True
            logging.critical("'keystore' not found in config.py!")
        if 'keystorepass' not in config and 'keystorepassfile' not in config:
            nosigningkey = True
            logging.critical("'keystorepass' not found in config.py!")
        if 'keypass' not in config and 'keypassfile' not in config:
            nosigningkey = True
            logging.critical("'keypass' not found in config.py!")
        if not os.path.exists(config['keystore']):
            nosigningkey = True
            logging.critical("'" + config['keystore'] + "' does not exist!")
        if nosigningkey:
            logging.warning("`fdroid update` requires a signing key, you can create one using:")
            logging.warning("\tfdroid update --create-key")
            sys.exit(1)

    repoel.setAttribute("pubkey", extract_pubkey().decode('utf-8'))
    root.appendChild(repoel)

    for appid in sortedids:
        app = apps[appid]

        if app.Disabled is not None:
            continue

        # Get a list of the apks for this app...
        apklist = []
        for apk in apks:
            if apk['id'] == appid:
                apklist.append(apk)

        if len(apklist) == 0:
            continue

        apel = doc.createElement("application")
        apel.setAttribute("id", app.id)
        root.appendChild(apel)

        addElement('id', app.id, doc, apel)
        if app.added:
            addElement('added', time.strftime('%Y-%m-%d', app.added), doc, apel)
        if app.lastupdated:
            addElement('lastupdated', time.strftime('%Y-%m-%d', app.lastupdated), doc, apel)
        addElement('name', app.Name, doc, apel)
        addElement('summary', app.Summary, doc, apel)
        if app.icon:
            addElement('icon', app.icon, doc, apel)

        def linkres(appid):
            if appid in apps:
                return ("fdroid.app:" + appid, apps[appid].Name)
            raise MetaDataException("Cannot resolve app id " + appid)

        addElement('desc',
                   metadata.description_html(app.Description, linkres),
                   doc, apel)
        addElement('license', app.License, doc, apel)
        if app.Categories:
            addElement('categories', ','.join(app.Categories), doc, apel)
            # We put the first (primary) category in LAST, which will have
            # the desired effect of making clients that only understand one
            # category see that one.
            addElement('category', app.Categories[0], doc, apel)
        addElement('web', app.WebSite, doc, apel)
        addElement('source', app.SourceCode, doc, apel)
        addElement('tracker', app.IssueTracker, doc, apel)
        addElementNonEmpty('changelog', app.Changelog, doc, apel)
        addElementNonEmpty('author', app.AuthorName, doc, apel)
        addElementNonEmpty('email', app.AuthorEmail, doc, apel)
        addElementNonEmpty('donate', app.Donate, doc, apel)
        addElementNonEmpty('bitcoin', app.Bitcoin, doc, apel)
        addElementNonEmpty('litecoin', app.Litecoin, doc, apel)
        addElementNonEmpty('flattr', app.FlattrID, doc, apel)

        # These elements actually refer to the current version (i.e. which
        # one is recommended. They are historically mis-named, and need
        # changing, but stay like this for now to support existing clients.
        addElement('marketversion', app.CurrentVersion, doc, apel)
        addElement('marketvercode', app.CurrentVersionCode, doc, apel)

        if app.AntiFeatures:
            af = app.AntiFeatures
            if af:
                addElementNonEmpty('antifeatures', ','.join(af), doc, apel)
        if app.Provides:
            pv = app.Provides.split(',')
            addElementNonEmpty('provides', ','.join(pv), doc, apel)
        if app.RequiresRoot:
            addElement('requirements', 'root', doc, apel)

        # Sort the apk list into version order, just so the web site
        # doesn't have to do any work by default...
        apklist = sorted(apklist, key=lambda apk: apk['versioncode'], reverse=True)

        # Check for duplicates - they will make the client unhappy...
        for i in range(len(apklist) - 1):
            if apklist[i]['versioncode'] == apklist[i + 1]['versioncode']:
                logging.critical("duplicate versions: '%s' - '%s'" % (
                    apklist[i]['apkname'], apklist[i + 1]['apkname']))
                sys.exit(1)

        current_version_code = 0
        current_version_file = None
        for apk in apklist:
            # find the APK for the "Current Version"
            if current_version_code < apk['versioncode']:
                current_version_code = apk['versioncode']
            if current_version_code < int(app.CurrentVersionCode):
                current_version_file = apk['apkname']

            apkel = doc.createElement("package")
            apel.appendChild(apkel)
            addElement('version', apk['version'], doc, apkel)
            addElement('versioncode', str(apk['versioncode']), doc, apkel)
            addElement('apkname', apk['apkname'], doc, apkel)
            if 'srcname' in apk:
                addElement('srcname', apk['srcname'], doc, apkel)
            for hash_type in ['sha256']:
                if hash_type not in apk:
                    continue
                hashel = doc.createElement("hash")
                hashel.setAttribute("type", hash_type)
                hashel.appendChild(doc.createTextNode(apk[hash_type]))
                apkel.appendChild(hashel)
            addElement('sig', apk['sig'], doc, apkel)
            addElement('size', str(apk['size']), doc, apkel)
            addElement('sdkver', str(apk['minSdkVersion']), doc, apkel)
            if 'targetSdkVersion' in apk:
                addElement('targetSdkVersion', str(apk['targetSdkVersion']), doc, apkel)
            if 'maxSdkVersion' in apk:
                addElement('maxsdkver', str(apk['maxSdkVersion']), doc, apkel)
            if 'added' in apk:
                addElement('added', time.strftime('%Y-%m-%d', apk['added']), doc, apkel)
            addElementNonEmpty('permissions', ','.join(apk['permissions']), doc, apkel)
            if 'nativecode' in apk:
                addElement('nativecode', ','.join(apk['nativecode']), doc, apkel)
            addElementNonEmpty('features', ','.join(apk['features']), doc, apkel)

        if current_version_file is not None \
                and config['make_current_version_link'] \
                and repodir == 'repo':  # only create these
            namefield = config['current_version_name_source']
            sanitized_name = re.sub('''[ '"&%?+=/]''', '', app.get_field(namefield))
            apklinkname = sanitized_name + '.apk'
            current_version_path = os.path.join(repodir, current_version_file)
            if os.path.islink(apklinkname):
                os.remove(apklinkname)
            os.symlink(current_version_path, apklinkname)
            # also symlink gpg signature, if it exists
            for extension in ('.asc', '.sig'):
                sigfile_path = current_version_path + extension
                if os.path.exists(sigfile_path):
                    siglinkname = apklinkname + extension
                    if os.path.islink(siglinkname):
                        os.remove(siglinkname)
                    os.symlink(sigfile_path, siglinkname)

    if options.pretty:
        output = doc.toprettyxml(encoding='utf-8')
    else:
        output = doc.toxml(encoding='utf-8')

    with open(os.path.join(repodir, 'index.xml'), 'wb') as f:
        f.write(output)

    if 'repo_keyalias' in config:

        if options.nosign:
            logging.info("Creating unsigned index in preparation for signing")
        else:
            logging.info("Creating signed index with this key (SHA256):")
            logging.info("%s" % repo_pubkey_fingerprint)

        # Create a jar of the index...
        jar_output = 'index_unsigned.jar' if options.nosign else 'index.jar'
        p = FDroidPopen(['jar', 'cf', jar_output, 'index.xml'], cwd=repodir)
        if p.returncode != 0:
            logging.critical("Failed to create {0}".format(jar_output))
            sys.exit(1)

        # Sign the index...
        signed = os.path.join(repodir, 'index.jar')
        if options.nosign:
            # Remove old signed index if not signing
            if os.path.exists(signed):
                os.remove(signed)
        else:
            args = [config['jarsigner'], '-keystore', config['keystore'],
                    '-storepass:file', config['keystorepassfile'],
                    '-digestalg', 'SHA1', '-sigalg', 'SHA1withRSA',
                    signed, config['repo_keyalias']]
            if config['keystore'] == 'NONE':
                args += config['smartcardoptions']
            else:  # smardcards never use -keypass
                args += ['-keypass:file', config['keypassfile']]
            p = FDroidPopen(args)
            if p.returncode != 0:
                logging.critical("Failed to sign index")
                sys.exit(1)

    # Copy the repo icon into the repo directory...
    icon_dir = os.path.join(repodir, 'icons')
    iconfilename = os.path.join(icon_dir, os.path.basename(config['repo_icon']))
    shutil.copyfile(config['repo_icon'], iconfilename)

    # Write a category list in the repo to allow quick access...
    catdata = ''
    for cat in categories:
        catdata += cat + '\n'
    with open(os.path.join(repodir, 'categories.txt'), 'w', encoding='utf8') as f:
        f.write(catdata)


def archive_old_apks(apps, apks, archapks, repodir, archivedir, defaultkeepversions):

    for appid, app in apps.items():

        if app.ArchivePolicy:
            keepversions = int(app.ArchivePolicy[:-9])
        else:
            keepversions = defaultkeepversions

        def filter_apk_list_sorted(apk_list):
            res = []
            for apk in apk_list:
                if apk['id'] == appid:
                    res.append(apk)

            # Sort the apk list by version code. First is highest/newest.
            return sorted(res, key=lambda apk: apk['versioncode'], reverse=True)

        def move_file(from_dir, to_dir, filename, ignore_missing):
            from_path = os.path.join(from_dir, filename)
            if ignore_missing and not os.path.exists(from_path):
                return
            to_path = os.path.join(to_dir, filename)
            shutil.move(from_path, to_path)

        logging.debug("Checking archiving for {0} - apks:{1}, keepversions:{2}, archapks:{3}"
                      .format(appid, len(apks), keepversions, len(archapks)))

        if len(apks) > keepversions:
            apklist = filter_apk_list_sorted(apks)
            # Move back the ones we don't want.
            for apk in apklist[keepversions:]:
                logging.info("Moving " + apk['apkname'] + " to archive")
                move_file(repodir, archivedir, apk['apkname'], False)
                move_file(repodir, archivedir, apk['apkname'] + '.asc', True)
                for density in all_screen_densities:
                    repo_icon_dir = get_icon_dir(repodir, density)
                    archive_icon_dir = get_icon_dir(archivedir, density)
                    if density not in apk['icons']:
                        continue
                    move_file(repo_icon_dir, archive_icon_dir, apk['icons'][density], True)
                if 'srcname' in apk:
                    move_file(repodir, archivedir, apk['srcname'], False)
                archapks.append(apk)
                apks.remove(apk)
        elif len(apks) < keepversions and len(archapks) > 0:
            required = keepversions - len(apks)
            archapklist = filter_apk_list_sorted(archapks)
            # Move forward the ones we want again.
            for apk in archapklist[:required]:
                logging.info("Moving " + apk['apkname'] + " from archive")
                move_file(archivedir, repodir, apk['apkname'], False)
                move_file(archivedir, repodir, apk['apkname'] + '.asc', True)
                for density in all_screen_densities:
                    repo_icon_dir = get_icon_dir(repodir, density)
                    archive_icon_dir = get_icon_dir(archivedir, density)
                    if density not in apk['icons']:
                        continue
                    move_file(archive_icon_dir, repo_icon_dir, apk['icons'][density], True)
                if 'srcname' in apk:
                    move_file(archivedir, repodir, apk['srcname'], False)
                archapks.remove(apk)
                apks.append(apk)


def add_apks_to_per_app_repos(repodir, apks):
    apks_per_app = dict()
    for apk in apks:
        apk['per_app_dir'] = os.path.join(apk['id'], 'fdroid')
        apk['per_app_repo'] = os.path.join(apk['per_app_dir'], 'repo')
        apk['per_app_icons'] = os.path.join(apk['per_app_repo'], 'icons')
        apks_per_app[apk['id']] = apk

        if not os.path.exists(apk['per_app_icons']):
            logging.info('Adding new repo for only ' + apk['id'])
            os.makedirs(apk['per_app_icons'])

        apkpath = os.path.join(repodir, apk['apkname'])
        shutil.copy(apkpath, apk['per_app_repo'])
        apksigpath = apkpath + '.sig'
        if os.path.exists(apksigpath):
            shutil.copy(apksigpath, apk['per_app_repo'])
        apkascpath = apkpath + '.asc'
        if os.path.exists(apkascpath):
            shutil.copy(apkascpath, apk['per_app_repo'])


config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("--create-key", action="store_true", default=False,
                        help="Create a repo signing key in a keystore")
    parser.add_argument("-c", "--create-metadata", action="store_true", default=False,
                        help="Create skeleton metadata files that are missing")
    parser.add_argument("--delete-unknown", action="store_true", default=False,
                        help="Delete APKs without metadata from the repo")
    parser.add_argument("-b", "--buildreport", action="store_true", default=False,
                        help="Report on build data status")
    parser.add_argument("-i", "--interactive", default=False, action="store_true",
                        help="Interactively ask about things that need updating.")
    parser.add_argument("-I", "--icons", action="store_true", default=False,
                        help="Resize all the icons exceeding the max pixel size and exit")
    parser.add_argument("-e", "--editor", default="/etc/alternatives/editor",
                        help="Specify editor to use in interactive mode. Default " +
                        "is /etc/alternatives/editor")
    parser.add_argument("-w", "--wiki", default=False, action="store_true",
                        help="Update the wiki")
    parser.add_argument("--pretty", action="store_true", default=False,
                        help="Produce human-readable index.xml")
    parser.add_argument("--clean", action="store_true", default=False,
                        help="Clean update - don't uses caches, reprocess all apks")
    parser.add_argument("--nosign", action="store_true", default=False,
                        help="When configured for signed indexes, create only unsigned indexes at this stage")
    parser.add_argument("--use-date-from-apk", action="store_true", default=False,
                        help="Use date from apk instead of current time for newly added apks")
    options = parser.parse_args()

    config = common.read_config(options)

    if not ('jarsigner' in config and 'keytool' in config):
        logging.critical('Java JDK not found! Install in standard location or set java_paths!')
        sys.exit(1)

    repodirs = ['repo']
    if config['archive_older'] != 0:
        repodirs.append('archive')
        if not os.path.exists('archive'):
            os.mkdir('archive')

    if options.icons:
        resize_all_icons(repodirs)
        sys.exit(0)

    # check that icons exist now, rather than fail at the end of `fdroid update`
    for k in ['repo_icon', 'archive_icon']:
        if k in config:
            if not os.path.exists(config[k]):
                logging.critical(k + ' "' + config[k] + '" does not exist! Correct it in config.py.')
                sys.exit(1)

    # if the user asks to create a keystore, do it now, reusing whatever it can
    if options.create_key:
        if os.path.exists(config['keystore']):
            logging.critical("Cowardily refusing to overwrite existing signing key setup!")
            logging.critical("\t'" + config['keystore'] + "'")
            sys.exit(1)

        if 'repo_keyalias' not in config:
            config['repo_keyalias'] = socket.getfqdn()
            common.write_to_config(config, 'repo_keyalias', config['repo_keyalias'])
        if 'keydname' not in config:
            config['keydname'] = 'CN=' + config['repo_keyalias'] + ', OU=F-Droid'
            common.write_to_config(config, 'keydname', config['keydname'])
        if 'keystore' not in config:
            config['keystore'] = common.default_config.keystore
            common.write_to_config(config, 'keystore', config['keystore'])

        password = common.genpassword()
        if 'keystorepass' not in config:
            config['keystorepass'] = password
            common.write_to_config(config, 'keystorepass', config['keystorepass'])
        if 'keypass' not in config:
            config['keypass'] = password
            common.write_to_config(config, 'keypass', config['keypass'])
        common.genkeystore(config)

    # Get all apps...
    apps = metadata.read_metadata()

    # Generate a list of categories...
    categories = set()
    for app in apps.values():
        categories.update(app.Categories)

    # Read known apks data (will be updated and written back when we've finished)
    knownapks = common.KnownApks()

    # Gather information about all the apk files in the repo directory, using
    # cached data if possible.
    apkcachefile = os.path.join('tmp', 'apkcache')
    if not options.clean and os.path.exists(apkcachefile):
        with open(apkcachefile, 'rb') as cf:
            apkcache = pickle.load(cf, encoding='utf-8')
        if apkcache.get("METADATA_VERSION") != METADATA_VERSION:
            apkcache = {}
    else:
        apkcache = {}

    delete_disabled_builds(apps, apkcache, repodirs)

    # Scan all apks in the main repo
    apks, cachechanged = scan_apks(apps, apkcache, repodirs[0], knownapks, options.use_date_from_apk)

    # Generate warnings for apk's with no metadata (or create skeleton
    # metadata files, if requested on the command line)
    newmetadata = False
    for apk in apks:
        if apk['id'] not in apps:
            if options.create_metadata:
                if 'name' not in apk:
                    logging.error(apk['id'] + ' does not have a name! Skipping...')
                    continue
                f = open(os.path.join('metadata', apk['id'] + '.txt'), 'w', encoding='utf8')
                f.write("License:Unknown\n")
                f.write("Web Site:\n")
                f.write("Source Code:\n")
                f.write("Issue Tracker:\n")
                f.write("Changelog:\n")
                f.write("Summary:" + apk['name'] + "\n")
                f.write("Description:\n")
                f.write(apk['name'] + "\n")
                f.write(".\n")
                f.close()
                logging.info("Generated skeleton metadata for " + apk['id'])
                newmetadata = True
            else:
                msg = apk['apkname'] + " (" + apk['id'] + ") has no metadata!"
                if options.delete_unknown:
                    logging.warn(msg + "\n\tdeleting: repo/" + apk['apkname'])
                    rmf = os.path.join(repodirs[0], apk['apkname'])
                    if not os.path.exists(rmf):
                        logging.error("Could not find {0} to remove it".format(rmf))
                    else:
                        os.remove(rmf)
                else:
                    logging.warn(msg + "\n\tUse `fdroid update -c` to create it.")

    # update the metadata with the newly created ones included
    if newmetadata:
        apps = metadata.read_metadata()

    # Scan the archive repo for apks as well
    if len(repodirs) > 1:
        archapks, cc = scan_apks(apps, apkcache, repodirs[1], knownapks, options.use_date_from_apk)
        if cc:
            cachechanged = True
    else:
        archapks = []

    # Some information from the apks needs to be applied up to the application
    # level. When doing this, we use the info from the most recent version's apk.
    # We deal with figuring out when the app was added and last updated at the
    # same time.
    for appid, app in apps.items():
        bestver = 0
        for apk in apks + archapks:
            if apk['id'] == appid:
                if apk['versioncode'] > bestver:
                    bestver = apk['versioncode']
                    bestapk = apk

                if 'added' in apk:
                    if not app.added or apk['added'] < app.added:
                        app.added = apk['added']
                    if not app.lastupdated or apk['added'] > app.lastupdated:
                        app.lastupdated = apk['added']

        if not app.added:
            logging.debug("Don't know when " + appid + " was added")
        if not app.lastupdated:
            logging.debug("Don't know when " + appid + " was last updated")

        if bestver == 0:
            if app.Name is None:
                app.Name = app.AutoName or appid
            app.icon = None
            logging.debug("Application " + appid + " has no packages")
        else:
            if app.Name is None:
                app.Name = bestapk['name']
            app.icon = bestapk['icon'] if 'icon' in bestapk else None
            if app.CurrentVersionCode is None:
                app.CurrentVersionCode = str(bestver)

    # Sort the app list by name, then the web site doesn't have to by default.
    # (we had to wait until we'd scanned the apks to do this, because mostly the
    # name comes from there!)
    sortedids = sorted(apps.keys(), key=lambda appid: apps[appid].Name.upper())

    # APKs are placed into multiple repos based on the app package, providing
    # per-app subscription feeds for nightly builds and things like it
    if config['per_app_repos']:
        add_apks_to_per_app_repos(repodirs[0], apks)
        for appid, app in apps.items():
            repodir = os.path.join(appid, 'fdroid', 'repo')
            appdict = dict()
            appdict[appid] = app
            if os.path.isdir(repodir):
                make_index(appdict, [appid], apks, repodir, False, categories)
            else:
                logging.info('Skipping index generation for ' + appid)
        return

    if len(repodirs) > 1:
        archive_old_apks(apps, apks, archapks, repodirs[0], repodirs[1], config['archive_older'])

    # Make the index for the main repo...
    make_index(apps, sortedids, apks, repodirs[0], False, categories)

    # If there's an archive repo,  make the index for it. We already scanned it
    # earlier on.
    if len(repodirs) > 1:
        make_index(apps, sortedids, archapks, repodirs[1], True, categories)

    if config['update_stats']:

        # Update known apks info...
        knownapks.writeifchanged()

        # Generate latest apps data for widget
        if os.path.exists(os.path.join('stats', 'latestapps.txt')):
            data = ''
            with open(os.path.join('stats', 'latestapps.txt'), 'r', encoding='utf8') as f:
                for line in f:
                    appid = line.rstrip()
                    data += appid + "\t"
                    app = apps[appid]
                    data += app.Name + "\t"
                    if app.icon is not None:
                        data += app.icon + "\t"
                    data += app.License + "\n"
            with open(os.path.join(repodirs[0], 'latestapps.dat'), 'w', encoding='utf8') as f:
                f.write(data)

    if cachechanged:
        apkcache["METADATA_VERSION"] = METADATA_VERSION
        with open(apkcachefile, 'wb') as cf:
            pickle.dump(apkcache, cf)

    # Update the wiki...
    if options.wiki:
        update_wiki(apps, sortedids, apks + archapks)

    logging.info("Finished.")

if __name__ == "__main__":
    main()
