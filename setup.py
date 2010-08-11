#!/usr/bin/python

# txopenid
# Copyright (C) 2007-2008 Phil Christensen
#
# See LICENSE for details

import os, os.path

from distutils.core import setup

assets_path = os.path.join(os.path.dirname(__file__), 'txopenid/assets')
txopenid_path = os.path.join(os.path.dirname(__file__), 'txopenid')

def load_paths(path):
	paths = []
	for dirpath, dirnames, filenames in os.walk(path):
		if(dirpath.find('.svn') != -1):
			continue
		for f in filenames:
			if(f.startswith('.')):
				continue
			if(f.endswith('.pyc')):
				continue
			paths.append(os.path.join(dirpath[len(txopenid_path) + 1:], f))
	return paths

dist = setup(
	name="txopenid",
	version="0.5",
	description="OpenID Server for Twisted",
	author="Phil Christensen",
 	author_email="phil@bubblehouse.org",
	url="https://launchpad.net/txopenid",
	packages = [
		'txopenid',
		'txopenid.assets',
		'txopenid.test',
		'twisted.plugins',
	],
	package_data = dict(
		txopenid = [
						'assets/*.xml',
						'assets/webroot/*.css',
					],
	),
)
