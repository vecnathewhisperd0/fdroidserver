#!/usr/bin/env python3
#
# metadata_fetcher.py - part of the FDroid server tools
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


import collections
import logging
import os
from argparse import ArgumentParser
from pathlib import Path
from typing import Optional

from PIL import Image, PngImagePlugin

from . import _, common, metadata
from .exception import FDroidException
from .metadata import App, Build

BLANK_PNG_INFO = PngImagePlugin.PngInfo()
ALLOWED_EXTENSIONS = ("png", "jpg", "jpeg")
GRAPHIC_NAMES = ("featureGraphic", "icon", "promoGraphic", "tvBanner")
SCREENSHOT_DIRS = (
    "phoneScreenshots",
    "sevenInchScreenshots",
    "tenInchScreenshots",
    "tvScreenshots",
    "wearScreenshots",
)


options = None
config = None


# TODO: Make sure that symlink is followed
class MetadataFetcher:
    name = ""

    def __init__(self, app: App):
        self.char_limits = config["char_limits"]
        self.appid = app.id
        self.app = app
        self.build: Build = app.Builds[-1] if app.Builds else None

        if options and "root" in vars(options) and options.root:
            self.repo = Path(options.root)
        else:
            build_dir = Path("build")
            if app.RepoType == "srclib":
                self.repo = build_dir / "srclib" / app.Repo
            else:
                self.repo = build_dir / self.appid

        self.root_path = self.get_root_path()
        self.locale = self.get_locale()

    def get_gradle_flavor(self) -> list[str]:
        """Get a list of gradle flavors from the latest build."""
        if self.build and "gradle" in self.build:
            flavor = self.build["gradle"]
            flavor = [f for f in flavor if f not in ("yes", "no", True, False)]
        else:
            flavor = []
        flavor.append("main")
        return flavor

    def get_root_path(self) -> list[Path]:
        """Get all locations of the available metadata."""
        return []

    def get_locale(self) -> list[str]:
        """Get a list of the available locales in the metadata."""
        return sorted(
            {
                p.name
                for root_path in self.root_path
                for p in root_path.iterdir()
                if p.is_dir()
            }
        )

    def _get_localized_dict(self, locale: str):
        """Get the dict to add localized store metadata to."""
        app = self.app
        if "localized" not in app:
            app["localized"] = collections.OrderedDict()
        if locale not in app["localized"]:
            app["localized"][locale] = collections.OrderedDict()
        return app["localized"][locale]

    def get_author_info_file_path(self, _root_path: Path) -> dict[str, Path]:
        """Get the path to the author info files."""
        return {}

    def get_text_file_path(self, _root_path: Path, _locale: str) -> dict[str, Path]:
        """Get the path to the text files of the given locale."""
        return {}

    def get_graphic_path(self, _root_path: Path, _locale: str) -> dict[str, Path]:
        """Get the path to the graphic files of the given locale."""
        return {}

    def get_screenshot_path(
        self,
        _root_path: Path,
        _locale: str,
    ) -> dict[str, list[Path]]:
        """Get the paths to the screenshot files of the given locale."""
        return {}

    @classmethod
    def get_allowed_image(self, path: Path) -> list[Path]:
        """Get all images in allowed format under the given directory."""
        # TODO: os.scandir() can save a system call when checking if an item is a file.
        return sorted(
            [
                file
                for file in path.glob("*.*")
                if file.is_file() and file.suffix[1:] in ALLOWED_EXTENSIONS
            ]
        )

    def read_author_info_file(self, key: str, path: Path):
        """Read author info from file into app dict."""
        if self.app.get(key, None):
            logging.warn(f"[{self.name}] {key} has been set for {self.appid}, skipping")
            return
        try:
            limit = self.char_limits["author"]
            with path.open(errors="replace") as fp:
                text = fp.read(limit * 2).strip()
            if len(text) > limit:
                logging.warn(
                    f"[{self.name}] {key} at {path} has {len(text)} chars,"
                    f" exceeds {limit} chars"
                )
            if text:
                self.app[key] = text[:limit]
        except Exception as e:
            logging.error(_("{path}: {error}").format(path=path, error=str(e)))

    def read_text_file(self, locale: str, key: str, path: Path):
        """Read text from file into app dict."""
        limit = self.char_limits[key]
        try:
            with path.open(errors="replace") as fp:
                if key in ("name", "summary", "video"):
                    text = fp.read(limit * 2).strip()
                else:
                    text = fp.read(limit * 2)
            if len(text) > limit:
                logging.warn(
                    f"[{self.name}] {key} for {locale} at {path} has {len(text)} chars,"
                    f" exceeds {limit} chars"
                )
        except Exception as e:
            logging.error(_("{path}: {error}").format(path=path, error=str(e)))
        localized = self._get_localized_dict(locale)
        if key == "whatsNew":
            if path.stem.isdecimal():
                if self.build:
                    if not self.build.get(key, None):
                        self.build[key] = collections.OrderedDict()
                    self.build[key][locale] = text[:limit]
                localized[key] = text[:limit]
            else:
                if not localized.get(key, None):
                    localized[key] = text[:limit]
        if len(text) > 0:
            localized[key] = text[:limit]

    def fetch(self):
        """Fetch metadata."""
        for root_path in self.root_path:
            for key, path in self.get_author_info_file_path(root_path).items():
                logging.debug(f"[{self.name}] Found {key} at {path}")
                self.read_author_info_file(key, path)

            for locale in self.locale:
                for key, path in self.get_text_file_path(root_path, locale).items():
                    logging.debug(f"[{self.name}] Found {key} for {locale} at {path}")
                    self.read_text_file(locale, key, path)

                for key, path in self.get_graphic_path(root_path, locale).items():
                    logging.debug(f"[{self.name}] Found {key} for {locale} at {path}")
                    self._get_localized_dict(locale)[key] = path

                for key, paths in self.get_screenshot_path(root_path, locale).items():
                    localized_dict = self._get_localized_dict(locale)
                    if key not in localized_dict:
                        localized_dict[key] = []
                    for path in paths:
                        logging.debug(
                            f"[{self.name}] Found {key} for {locale} at {path}"
                        )
                        localized_dict[key].append(path)


class CustomMetadataFetcher(MetadataFetcher):
    """
    Custom metadata fetcher.

    This metadata format is only used by F-Droid and shown as follows:
    .
    ├── name.txt
    ├── summary.txt
    ├── description.txt
    ├── video.txt
    ├── changelogs
    │   └── <version code>.txt
    ├── icon.png
    ├── featureGraphic.png
    ├── phoneScreenshots
    │   ├── 1.png
    │   ├── 2.png
    │   ...
    ├── sevenInchScreenshots/
    ├── tenInchScreenshots/
    ├── tvScreenshots/
    └── wearScreenshots/

    The images can have .png, .jpg and .jpeg extension.
    """

    def get_text_file_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        metadata = {
            key: file
            for key in ("name", "summary", "description", "video")
            if (file := root_path / locale / f"{key}.txt").is_file()
        }
        if (
            changelog := root_path
            / locale
            / f"changelogs/{self.app.CurrentVersionCode}.txt"
        ).is_file():
            metadata["whatsNew"] = changelog
        return metadata

    def get_graphic_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        return {
            key: file
            for file in self.get_allowed_image(root_path / locale)
            if (key := file.stem) in GRAPHIC_NAMES
        }

    def get_screenshot_path(
        self, root_path: Path, locale: str
    ) -> dict[str, list[Path]]:
        return {
            key: files
            for key in SCREENSHOT_DIRS
            if (files := self.get_allowed_image(root_path / locale / key))
        }


class RepoMetadataFetcher(MetadataFetcher):
    """
    Repo image fetcher.

    This fetcher is used to fetch images in repo directory.
    The file structure is the same as custom metadata structure.
    """

    name = "repo"

    def get_root_path(self) -> list[Path]:
        path = Path(f"repo/{self.appid}")
        return [path] if path.is_dir() else []

    def get_graphic_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        return CustomMetadataFetcher.get_graphic_path(self, root_path, locale)

    def get_screenshot_path(
        self, root_path: Path, locale: str
    ) -> dict[str, list[Path]]:
        return CustomMetadataFetcher.get_screenshot_path(self, root_path, locale)


class FastlaneMetadataFetcher(MetadataFetcher):
    """
    Metadata fetcher for Fastlane metadata.

    The structure is located in these position:
        `build/<appid>/fastlane/metadata/android/<locale>`
        `build/<appid>/src/fastlane/metadata/android/<locale>`
        `build/<appid>/<subdir>/fastlane/metadata/android/<locale>`
        `build/<appid>/<subdir>/src/<flavor>/fastlane/metadata/android/<locale>`
    and shown as follows:
    .
    ├── title.txt
    ├── short_description.txt
    ├── full_description.txt
    ├── video.txt
    ├── changelogs
    │   ├── <version code>.txt
    │   └── default.txt
    └── images
        ├── icon.png
        ├── featureGraphic.png
        ├── promoGraphic.png
        ├── tvBanner.png
        ├── phoneScreenshots
        │   ├── 1.png
        │   ├── 2.png
        │   ...
        ├── sevenInchScreenshots/
        ├── tenInchScreenshots/
        ├── tvScreenshots/
        └── wearScreenshots/

    The images can have .png, .jpg and .jpeg extension.
    """

    name = "fastlane"

    def get_root_path(self) -> list[Path]:
        paths = []
        root = self.repo

        paths.append(root)
        paths.append(root / "src")
        paths.append(root / "android/app")  # For Flutter

        if self.build and self.build.subdir:
            root = root / self.build.subdir
            paths.append(root)
            paths.append(root / "android/app")  # For Flutter

        flavors = self.get_gradle_flavor()
        paths.extend([root / "src" / f for f in flavors])
        return [
            p for path in paths if (p := path / "fastlane/metadata/android").is_dir()
        ]

    def get_text_file_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        file_name = {
            "name": "title",
            "summary": "short_description",
            "description": "full_description",
            "video": "video",
        }
        metadata = {
            key: file
            for key, name in file_name.items()
            if (file := root_path / locale / f"{name}.txt").is_file()
        }
        if (
            self.build
            and (
                changelog := root_path
                / locale
                / f"changelogs/{self.app.CurrentVersionCode}.txt"
            ).is_file()
        ):
            metadata["whatsNew"] = changelog
        elif (changelog := root_path / locale / "changelogs/default.txt").is_file():
            metadata["whatsNew"] = changelog
        return metadata

    def get_graphic_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        return {
            key: file
            for file in self.get_allowed_image(root_path / locale / "images")
            if (key := file.stem) in GRAPHIC_NAMES
        }

    def get_screenshot_path(
        self, root_path: Path, locale: str
    ) -> dict[str, list[Path]]:
        return {
            key: files
            for key in SCREENSHOT_DIRS
            if (files := self.get_allowed_image(root_path / locale / "images" / key))
        }


class VendoredMetadataFetcher(MetadataFetcher):
    """
    Metadata fetcher for vendored metadata in fdroiddata.

    This metadata format is only used by F-Droid and has the same structure as the
    custom metadata or Fastlane. The structure is located in
    `metadata/<appid>/<locale>`.
    """

    name = "vendored"

    def get_root_path(self) -> list[Path]:
        path = Path(f"metadata/{self.appid}")
        return [path] if path.is_dir() else []

    def get_text_file_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        return FastlaneMetadataFetcher.get_text_file_path(
            self, root_path, locale
        ) | CustomMetadataFetcher.get_text_file_path(self, root_path, locale)

    def get_graphic_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        return FastlaneMetadataFetcher.get_graphic_path(
            self, root_path, locale
        ) | CustomMetadataFetcher.get_graphic_path(self, root_path, locale)

    def get_screenshot_path(
        self, root_path: Path, locale: str
    ) -> dict[str, list[Path]]:
        return FastlaneMetadataFetcher.get_screenshot_path(
            self, root_path, locale
        ) | CustomMetadataFetcher.get_screenshot_path(self, root_path, locale)


class InternalMetadataFetcher(VendoredMetadataFetcher):
    """
    Metadata fetcher for the internal metadata structrue.

    This metadata format is only used by F-Droid and has the same structure as the
    custom metadata or Fastlane. The structure is located in
    `build/<appid>/metadata/<locale>`.
    """

    name = "internal"

    def get_root_path(self) -> list[Path]:
        path = self.repo / "metadata"
        return [path] if path.is_dir() else []


class TripleTMetadataFetcher(MetadataFetcher):
    """
    Metadata fetcher for the Triple-T metadata structrue.

    Used by Gradle Play Publisher.

    The structure is located in `build/<appid>/<subdir>/src/<flavor>/play`
    and shown as follows:
    .
    ├── contact-email.txt
    ├── contact-website.txt
    ├── release-notes/<locale>/default.txt
    └── listings/<locale>
        ├── title.txt
        ├── short-description.txt
        ├── full-description.txt
        ├── video-url.txt
        └── graphics
            ├── icon
            │   └── *.png
            ├── feature-graphic/
            ├── promo-graphic/
            ├── tv-banner/
            ├── phone-screenshots/
            ├── tablet-screenshots/
            ├── large-tablet-screenshots/
            ├── tv-screenshots/
            └── wear-screenshots/

    The images can have .png, .jpg and .jpeg extension.
    """

    name = "triple-t"

    def get_root_path(self) -> list[Path]:
        if not self.build:
            # TODO: guess the path
            return []
        root = self.repo
        if self.build.subdir:
            root = root / self.build.subdir

        flavors = self.get_gradle_flavor()

        return [
            path
            # TODO: maybe the dir name has more than one flavor
            for root in [root / "src", root / "android/app/src"]
            + list(root.glob("*/src"))
            if root.is_dir()
            for srcset in root.iterdir()
            if srcset.name in flavors and (path := srcset / "play").is_dir()
        ]

    def get_locale(self) -> list[str]:
        return sorted(
            {
                p.name
                for root_path in self.root_path
                if (listings := root_path / "listings").is_dir()
                for p in listings.iterdir()
                if p.is_dir()
            }
        )

    def get_author_info_file_path(self, root_path: Path) -> dict[str, Path]:
        file_name = {
            "authorEmail": "contact-email",
            "authorWebSite": "contact-website",
        }
        return {
            key: file
            for key, name in file_name.items()
            if (file := root_path / f"{name}.txt").is_file()
        }

    def get_text_file_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        file_name = {
            "name": "title",
            "summary": "short-description",
            "description": "full-description",
            "video": "video-url",
        }
        metadata = {
            key: file
            for key, name in file_name.items()
            if (file := root_path / "listings" / locale / f"{name}.txt").is_file()
        }
        if (
            changelog := root_path / "release-notes" / locale / "default.txt"
        ).is_file():
            metadata["whatsNew"] = changelog
        return metadata

    def get_graphic_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        dir_name = {
            "icon": "icon",
            "featureGraphic": "feature-graphic",
            "promoGraphic": "promo-graphic",
            "tvBanner": "tv-banner",
        }
        return {
            key: files[0]
            for key, dir in dir_name.items()
            if (
                files := self.get_allowed_image(
                    root_path / "listings" / locale / "graphics" / dir
                )
            )
        }

    def get_screenshot_path(
        self, root_path: Path, locale: str
    ) -> dict[str, list[Path]]:
        dir_name = {
            "phoneScreenshots": "phone-screenshots",
            "sevenInchScreenshots": "tablet-screenshots",
            "tenInchScreenshots": "large-tablet-screenshots",
            "tvScreenshots": "tv-screenshots",
            "wearScreenshots": "wear-screenshots",
        }
        return {
            key: files
            for key, dir in dir_name.items()
            if (
                files := self.get_allowed_image(
                    root_path / "listings" / locale / "graphics" / dir
                )
            )
        }


class TripleT1MetadataFetcher(TripleTMetadataFetcher):
    """
    Metadata fetcher for the Triple-T metadata structrue.

    Used by Gradle Play Publisher before version 2.

    The structure is located in `build/<appid>/<subdir>/src/<flavor>/play`
    and shown as follows:
    .
    ├── contactEmail
    ├── contactWebsite
    └── <locale>
        ├── whatsnew
        └── listing
            ├── title
            ├── shortdescription
            ├── fulldescription
            ├── video
            ├── icon
            │   └── *.png
            ├── featureGraphic/
            ├── promoGraphic/
            ├── tvBanner/
            ├── phoneScreenshots/
            ├── sevenInchScreenshots/
            ├── tenInchScreenshots/
            ├── tvScreenshots/
            └── wearScreenshots/

    The images can have .png, .jpg and .jpeg extension.
    """

    name = "triple-t1"

    def get_locale(self) -> list[str]:
        return sorted(
            {
                p.name
                for root_path in self.root_path
                for p in root_path.iterdir()
                if p.is_dir()
            }
        )

    def get_author_info_file_path(self, root_path: Path) -> dict[str, Path]:
        file_name = {
            "authorEmail": "contactEmail",
            "authorWebSite": "contactWebsite",
        }
        return {
            key: file
            for key, name in file_name.items()
            if (file := root_path / name).is_file()
        }

    def get_text_file_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        file_name = {
            "name": "title",
            "summary": "shortdescription",
            "description": "fulldescription",
            "video": "video",
        }
        metadata = {
            key: file
            for key, name in file_name.items()
            if (file := root_path / locale / "listing" / name).is_file()
        }
        if (changelog := root_path / locale / "whatsnew").is_file():
            metadata["whatsNew"] = changelog
        return metadata

    def get_graphic_path(self, root_path: Path, locale: str) -> dict[str, Path]:
        return {
            key: files[0]
            for key in GRAPHIC_NAMES
            if (files := self.get_allowed_image(root_path / locale / "listing" / key))
        }

    def get_screenshot_path(
        self, root_path: Path, locale: str
    ) -> dict[str, list[Path]]:
        return {
            key: files
            for key in SCREENSHOT_DIRS
            if (files := self.get_allowed_image(root_path / locale / "listing" / key))
        }


# The last fetcher has the highest priority
FETCHERS = [
    RepoMetadataFetcher,
    InternalMetadataFetcher,
    FastlaneMetadataFetcher,
    TripleT1MetadataFetcher,
    TripleTMetadataFetcher,
    VendoredMetadataFetcher,
]


def get_fetcher(type: str) -> Optional[MetadataFetcher]:
    """Get the fetcher for a structure."""
    supported_fetcher = {Fetcher.name: Fetcher for Fetcher in FETCHERS}
    return supported_fetcher.get(type, None)


def fetch_metadata(app: App):
    """Fetch metadata with all supported fetchers."""
    for Fetcher in FETCHERS:
        Fetcher(app).fetch()


def strip_and_copy_image(src, dst):
    """Remove any metadata from image and copy it to new path.

    Sadly, image metadata like EXIF can be used to exploit devices.
    It is not used at all in the F-Droid ecosystem, so its much safer
    just to remove it entirely.

    This uses size+mtime to check for a new file since this process
    actually modifies the resulting file to strip out the EXIF.

    outpath can be path to either a file or dir.  The dir that outpath
    refers to must exist before calling this.

    Potential source of Python code to strip JPEGs without dependencies:
    http://www.fetidcascade.com/public/minimal_exif_writer.py
    """
    if not src.is_file():
        logging.warning(
            _("File disappeared while processing it: {path}").format(path=src)
        )
        return

    if dst.is_dir():
        logging.error("{dst} is a directory")
        return

    if dst.is_file():
        in_stat = src.stat()
        out_stat = dst.stat()
        if in_stat.st_mtime == out_stat.st_mtime:
            logging.debug(f"{src} not changed, skipping")
            return

    logging.debug(f"Copying {src} {dst}")

    if src.suffix[1:] == "png":
        try:
            with src.open("rb") as fp:
                in_image = Image.open(fp)
                in_image.save(
                    dst,
                    "PNG",
                    optimize=True,
                    pnginfo=BLANK_PNG_INFO,
                    icc_profile=None,
                )
        except Exception as e:
            logging.error(_("Failed copying {path}: {error}".format(path=src, error=e)))
            return
    elif src.suffix[1:] in ("jpg", "jpeg"):
        try:
            with src.open("rb") as fp:
                in_image = Image.open(fp)
                data = list(in_image.getdata())
                out_image = Image.new(in_image.mode, in_image.size)
            out_image.putdata(data)
            out_image.save(dst, "JPEG", optimize=True)
        except Exception as e:
            logging.error(_("Failed copying {path}: {error}".format(path=src, error=e)))
            return
    else:
        raise FDroidException(
            _('Unsupported file type "{extension}" for repo graphic').format(
                extension=src.suffix[1:]
            )
        )
    stat_result = src.stat()
    os.utime(dst, times=(stat_result.st_atime, stat_result.st_mtime))


def copy_and_index_image(app: App):
    """Copy images to repo and index them."""
    if "localized" not in app:
        return
    localized = app["localized"]
    for locale in localized:
        for key, value in localized[locale].items():
            if key in GRAPHIC_NAMES:
                dst = Path("repo") / app.id / locale / f"{key}{value.suffix}"
                if dst != value:
                    dst.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    strip_and_copy_image(value, dst)
                if not dst.is_file():
                    del localized[locale][key]
                    continue
                index_file = dst.with_stem(f"{dst.stem}_{common.sha256base64(dst)}")
                if not index_file.is_file():
                    os.link(dst, index_file, follow_symlinks=False)
                localized[locale][key] = index_file.name

                # index-v2
                if key == "icon":
                    key = "iconv2"
                if key not in app or not isinstance(app[key], collections.OrderedDict):
                    app[key] = collections.OrderedDict()
                app[key][locale] = common.file_entry(index_file)

            elif key in SCREENSHOT_DIRS:
                dst_dir = Path("repo") / app.id / locale / key
                dst_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
                # Remove images with the same name
                value = {path.name: path for path in value}
                dsts = []
                for path in value.values():
                    dst = dst_dir / path.name
                    if dst != path:
                        strip_and_copy_image(path, dst)
                    if dst.is_file():
                        dsts.append(dst)
                if dsts:
                    localized[locale][key] = [dst.name for dst in dsts]
                else:
                    del localized[locale][key]
                    continue

                # index-v2
                key = key.replace("Screenshots", "")
                if "screenshots" not in app:
                    app["screenshots"] = collections.OrderedDict()
                if key not in app["screenshots"]:
                    app["screenshots"][key] = collections.OrderedDict()
                app["screenshots"][key][locale] = [
                    common.file_entry(dst) for dst in dsts
                ]
            # TODO: Remove not indexed images


def get_app(pair: str) -> App:
    """
    Get app metadata from an appid version code pair.

    The appid version code pair should consist an appid and a version code,
    splitted with a :. An App instance with only the corresponding build block
    is returned. If the version code is not provided then the latest version
    will be returned.
    """
    p = pair.split(":")
    if len(p) == 1:
        appid, vercode = p[0], None
    elif len(p) == 2:
        appid = p[0]
        vercode = int(p[1])
    else:
        logging.error(f"Invalid appid: {pair}")
        return

    app = metadata.parse_metadata(Path(f"metadata/{appid}.yml"))
    metadata.check_metadata(app)

    # Only keep the specified build
    if vercode:
        if builds := app.get("Builds", []):
            for build in builds:
                if build.versionCode == vercode:
                    app.Builds = [build]
                    app.CurrentVersionCode = vercode
                    break
            else:
                logging.critical(
                    f"Specified version code {vercode} is not found in {appid}"
                )
                raise FDroidException(_("Found invalid versionCodes for some apps"))
        else:
            logging.error(f"Version code is specified but there is no build in {appid}")
    else:
        builds = app.get("Builds", [])
        # TODO: Should we check if the build is disabled?
        build = builds[-1] if builds else None
        app.Builds = [build] if build else []

    return app


# TODO: Output a HTML file of rendered metadata?
def main():
    global options, config

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID[:VERCODE] ...]")
    common.setup_global_opts(parser)
    parser.add_argument(
        "appid",
        nargs="*",
        help=_("application ID with optional versionCode in the form APPID[:VERCODE]"),
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=False,
        help=_("Force fetch metadata of disabled apps and builds."),
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        default=False,
        help=_("Only read text and check images but doesn't copy images to /repo."),
    )
    parser.add_argument(
        "-t",
        "--type",
        help=_("The type of the fetcher to be used. By default all fetchers are used."),
    )
    parser.add_argument(
        "-r",
        "--root",
        help=_(
            "The root of the source code. "
            "If this is set, the source code should be prepared by the user."
        ),
    )

    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W
    config = common.read_config(options)

    Fetcher = None
    if options.type:
        Fetcher = get_fetcher(options.type)
        if not Fetcher:
            logging.error(f"Unsupported metadata structure: {options.type}")
            return

    # initialize/load configuration values
    common.get_config(opts=options)
    common.options = options

    apps = (
        map(get_app, options.appid)
        if options.appid
        else metadata.read_metadata().values()
    )

    build_dir = Path("build")
    if not build_dir.is_dir():
        logging.info("Creating build directory")
        build_dir.mkdir()

    for app in apps:
        if app.Disabled and not options.force:
            logging.info(_("Skipping {appid}: disabled").format(appid=app.id))
            continue

        if app.RepoType == "srclib":
            build_dir = build_dir / "srclib" / app.Repo
        else:
            build_dir = build_dir / app.id

        if options.root:
            if not Path(options.root).is_dir():
                logging.critical(f"The specified repo {options.root} does not exist!")
                return
            logging.info("Using specified repo, skipping repo clone")
        elif Fetcher and Fetcher.name == "vendored":
            logging.info("Fetching vendored metadata only, skipping repo clone")
        else:
            # Prepare the source code
            if app.Builds:
                logging.info(_("Processing {appid}").format(appid=app.id))
                # Set up vcs interface and make sure we have the latest code...
                vcs = common.getvcs(app.RepoType, app.Repo, build_dir)
                vcs.gotorevision(app.Builds[0].commit)

        if Fetcher:
            logging.info(f"Fetching metadata for {app.id} with {Fetcher.name} fetcher")
            Fetcher(app).fetch()
        else:
            logging.info(f"Fetching metadata for {app.id}")
            fetch_metadata(app)

        if not options.dry_run:
            copy_and_index_image(app)


if __name__ == "__main__":
    main()
