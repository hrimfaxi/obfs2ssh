#!/usr/bin/python

from distutils.core import setup
import os

if os.name == 'nt':
	import py2exe

setup(name='obfs2SSH',
      windows=['obfs2SSH'],
      version='0.0',
      description="Obfsproxy + SSH tunnel to avoid DPI detection",
      author = 'Hrimfaxi',
      author_email = 'outmatch@gmail.com',
      url='http://code.google.com/p/obfs2ssh/',
      scripts = ['obfs2SSH' ],
      py_modules=['obfs2SSH'],
)
