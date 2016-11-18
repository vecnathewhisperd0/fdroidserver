# F-Droid Server

[![build status](https://gitlab.com/fdroid/fdroidserver/badges/master/build.svg)](https://gitlab.com/fdroid/fdroidserver/builds)

Server for [F-Droid](https://f-droid.org), the Free Software repository system
for Android.

The F-Droid server tools provide various scripts and tools that are used to
maintain the main [F-Droid application repository](https://f-droid.org/repository/browse).
You can use these same tools to create your own additional or alternative
repository for publishing, or to assist in creating, testing and submitting
metadata to the main repository.

For documentation, please see the docs directory.

Alternatively, visit [https://f-droid.org/manual/](https://f-droid.org/manual/).

### What is F-Droid?

F-Droid is an installable catalogue of FOSS (Free and Open Source Software)
applications for the Android platform. The client makes it easy to browse,
install, and keep track of updates on your device.

### Installing

Note that only Python 3 is supported. We recommend version 3.4 or later.

The easiest way to install the `fdroidserver` tools is on Ubuntu, Mint or other
Ubuntu based distributions, you can install using:

	sudo apt-get install fdroidserver

For older Ubuntu releases or to get the latest version, you can get
`fdroidserver` from the Guardian Project PPA (the signing key
fingerprint is `6B80 A842 07B3 0AC9 DEE2 35FE F50E ADDD 2234 F563`)

	sudo add-apt-repository ppa:guardianproject/ppa
	sudo apt-get update
	sudo apt-get install fdroidserver

On OSX, `fdroidserver` is available from third party package managers,
like Homebrew, MacPorts, and Fink:

	brew install fdroidserver

For Arch-Linux is a package in the AUR available. If you have installed
`yaourt` or something similiar, you can do:

	yaourt -S fdroidserver

For any platform where Python's `easy_install` is an option (e.g. OSX
or Cygwin, you can use it:

	sudo easy_install fdroidserver

Python's `pip` also works:

	sudo pip3 install fdroidserver

The combination of `pyvenv` and `pip` is great for testing out the
latest versions of `fdroidserver`. Using `pip`, `fdroidserver` can
even be installed straight from git. First, make sure you have
installed the python header files, venv and pip. They should be
included in your OS's default package manager or you can install them
via other mechanisms like Brew/dnf/pacman/emerge/Fink/MacPorts.

For Debian based distributions:

	apt-get install python3-dev python3-pip python3-venv libjpeg-dev zlib1g-dev
	apt-get install libffi-dev libssl-dev

Then here's how to install:

	git clone https://gitlab.com/fdroid/fdroidserver.git
	cd fdroidserver
	pyvenv env/
	source env/bin/activate
	pip3 install -e .
	python3 setup.py install
