#!/usr/bin/python

from subprocess import call
import sys

from com.dtmilano.android.viewclient import ViewClient

vc = ViewClient(*ViewClient.connectToDeviceOrExit())

button = vc.findViewWithText("OFF")

if button:
    (x, y) = button.getXY()
    button.touch()
else:
    print "Button not found. Is the app currently running?"
    exit()

print "Done!"
