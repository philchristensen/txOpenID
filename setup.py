#!/usr/bin/python

# txopenid
# Copyright (C) 2007-2008 Phil Christensen
#
# See LICENSE for details

from distribute_setup import use_setuptools
use_setuptools()

import os
from setuptools import setup, find_packages

dist = setup(
	name="txopenid",
	version="0.5",
	
	include_package_data	= True,
	zip_safe				= False,
	packages				= find_packages(),
	
	install_requires = [
		'setuptools_git>=0.4.2',
		'twisted>=11.0.0',
		'nevow>=0.10.0',
		'MySQL-python>=1.2.3',
	],
	
	entry_points	= {
		'setuptools.file_finders'	: [
			'git = setuptools_git:gitlsfiles',
		],
	},
	
	description="OpenID Server for Twisted",
	author="Phil Christensen",
	author_email="phil@bubblehouse.org",
	url="https://github.com/philchristensen/txopenid",
)
