# txopenid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

"""
Test cases and utilities for trial.
"""

from nevow import testutil
from nevow.util import qual

class TestUser(dict):
	def __init__(self, data=None, identify=True, trust=True):
		if(data):
			self.update(data)
		self.identify = identify
		self.trust = trust
	
	def hasIdentity(self, identity):
		return self.identify
	
	def trustsRoot(self, root):
		return self.trust
