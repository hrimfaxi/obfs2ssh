#!/usr/bin/python2

from distutils.core import setup

try:
	import py2exe
except ImportError as e:
	pass

setup(name='obfs2SSH',
      console=['obfs2SSH'],
      version='0.1',
      description="Obfsproxy + SSH tunnel to avoid DPI detection",
      author = 'Hrimfaxi',
      author_email = 'outmatch@gmail.com',
      url='http://code.google.com/p/obfs2ssh/',
      scripts = ['obfs2SSH' ],
      py_modules=['obfs2SSH'],
      license= 'GPL',
)
