# -*- coding: utf-8 -*-

name = 'tk_framework_desktopserver'

version = "1.3.10"

description = 'tk-framework-desktopserver'

authors = ['ShotgunSoftware']

tools = []

requires = []

build_command = "python {root}/rezbuild.py {install}"


def commands():
    # Allows to override the bundled tk-framework-desktopserver and use any
    # one you want. This disables updates.
    env.SGTK_DESKTOP_SERVER_LOCATION = '{root}'


format_version = 2
