# txopenid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

"""
User model.
"""

from txopenid import db

class User(dict):
	"""
	Simple dict subclass to represent user records.
	"""
	def __init__(self, data=None):
		"""
		Create a new User object.
		"""
		if(data):
			self.update(data)
		# This will be set by the db code
		self.pool = None
	
	def getIdentities(self):
		"""
		Return a list of this user's identity records.
		"""
		return self.pool.getUserIdentities(self)
	
	def hasIdentity(self, identity):
		"""
		Does this user have the provided identity?
		"""
		return self.pool.checkUserIdentity(self, identity)
	
	def getTrustedRoots(self):
		"""
		Return a list of this user's trusted root records.
		"""
		return self.pool.getUserTrustedRoots(self)
	
	def trustsRoot(self, root):
		"""
		Does this user trust the provided root?
		"""
		return self.pool.checkUserTrust(self, root)
