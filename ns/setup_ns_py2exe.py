#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup
import py2exe, sys, os


sys.argv.append('py2exe')

py2exe_options = {
    'bundle_files': 1,
    'compressed': True,
    'optimize': 2,
    'packages': ['dns'],
    'dll_excludes': ['w9xpopen.exe'], # exclude win95 98 dll files
    'includes': [], # additional modules
    'excludes': ['Carbon', 'Carbon.Files', 'Crypto.PublicKey.DSA', 'Crypto.PublicKey.RSA', 'Crypto.Util.number', 'ecdsa', 'ecdsa.ecdsa', 'ecdsa.ellipticcurve', 'ecdsa.keys', 'idna', 'winreg']  # exluded modules
    #'excludes': []
}

setup(
  options = {
            'py2exe': py2exe_options,
            },
  console = ["ns.py"],
  zipfile = None,
)