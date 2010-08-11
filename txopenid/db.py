# txopenid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

"""
DB persistence layer.

At this time, the persistence features of txOpenID are fairly dependant
on MySQL. However, every attempt has been made to keep MySQL-specific
code in this module, in hopes of making it easy to support new DB types.
"""

import time

from MySQLdb import cursors

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.enterprise import adbapi

class Connection(object):
	"""
	A representation of a database connection.
	
	This is pretty much just a wrapper around 
	L{twisted.enterprise.adbapi.ConnectionPool}. This class
	just adds a bunch of convenience methods for the limited
	amount of DB access needed by txOpenID.
	"""
	
	def __init__(self, **kwargs):
		"""
		Create a new connection to the DB.
		"""
		self.conn = adbapi.ConnectionPool('MySQLdb',
										host=kwargs.get('host', 'localhost'),
										db=kwargs.get('db', 'txopenid'),
										user=kwargs.get('user', 'txopenid'),
										passwd=kwargs.get('passwd', 'txopenid'),
										cursorclass=cursors.SSDictCursor,
										cp_reconnect=True,
										cp_noisy=False,
										cp_min=3,
										cp_max=10,
									)
	
	@inlineCallbacks
	def checkUserIdentity(self, user, identity):
		"""
		Does the provided user have the provided identity?
		
		@param user: the user in question
		@type user: L{txopenid.user.User}
		
		@param identity: the identity to check
		@type user: str
		
		@return: True if there were no errors.
		"""
		identity_query = "SELECT 1 FROM identity WHERE user_id = %s and url = %s"
		result = yield self.conn.runQuery(identity_query, [user['id'], identity])
		if(result):
			returnValue(True)
		returnValue(False)
	
	@inlineCallbacks
	def getUserIdentities(self, user):
		"""
		Return a list of identities for this user.
		
		@param user: the user in question
		@type user: L{txopenid.user.User}
		
		@return: a list of identity records
		@rtype: list(dict(column => value))
		"""
		identity_query = "SELECT * FROM identity WHERE user_id = %s"
		result = yield self.conn.runQuery(identity_query, [user['id']])
		returnValue(result)
	
	@inlineCallbacks
	def getUserIdForIdentity(self, identity):
		"""
		Return the user who posesses the provided identity.
		
		@param identity: the identity to check for
		@type user: str
		
		@return: the registered user's ID
		"""
		identity_query = "SELECT user_id FROM identity WHERE url = %s"
		result = yield self.conn.runQuery(identity_query, [identity])
		if(result):
			returnValue(result[0]['user_id'])
		returnValue(None)
	
	@inlineCallbacks
	def saveUserIdentity(self, user, identity):
		"""
		Add the provided identity to the user's list.
		
		@param user: the user in question
		@type user: L{txopenid.user.User}
		
		@param identity: the identity to save
		@type user: str
		
		@return: True if there were no errors.
		"""
		identity_operation = "INSERT INTO identity (user_id, url) VALUES (%s, %s)"
		yield self.conn.runOperation(identity_operation, [user['id'], identity])
		returnValue(True)
	
	@inlineCallbacks
	def removeUserIdentities(self, user, identity_ids):
		"""
		Remove these identities for this user.
		
		@param user: the current user
		@type user: L{txopenid.user.User}
		
		@param identity_ids: a list of IDs to remove
		@type identity_ids: int or list(int)
		
		@return: True if there were no errors.
		"""
		if not(isinstance(identity_ids, (list, tuple))):
			identity_ids = [identity_ids]
		identity_operation = "DELETE FROM identity WHERE user_id = %%s AND id IN (%s)" % ','.join(['%s']*len(identity_ids))
		yield self.conn.runOperation(identity_operation, [user['id']] + identity_ids)
		returnValue(True)
	
	@inlineCallbacks
	def checkUserTrust(self, user, root):
		"""
		Does the provided user trust provided root URL?
		
		@param user: the user in question
		@type user: L{txopenid.user.User}
		
		@param identity: the root URL to check
		@type user: str
		
		@return: True if there were no errors.
		"""
		trust_query = "SELECT 1 FROM trusted_root WHERE user_id = %s and url = %s"
		result = yield self.conn.runQuery(trust_query, [user['id'], root])
		if(result):
			returnValue(True)
		returnValue(False)
	
	@inlineCallbacks
	def getUserTrustedRoots(self, user):
		"""
		Return a list of trusted roots for this user.
		
		@param user: the user in question
		@type user: L{txopenid.user.User}
		
		@return: a list of trusted_root records
		@rtype: list(dict(column => value))
		"""
		trust_query = "SELECT * FROM trusted_root WHERE user_id = %s"
		result = yield self.conn.runQuery(trust_query, [user['id']])
		returnValue(result)
	
	@inlineCallbacks
	def saveUserRoot(self, user, root):
		"""
		Add the provided root to the user's list.
		
		@param user: the user in question
		@type user: L{txopenid.user.User}
		
		@param identity: the root to trust
		@type user: str
		
		@return: True if there were no errors.
		"""
		root_operation = "INSERT INTO trusted_root (user_id, url) VALUES (%s, %s)"
		yield self.conn.runOperation(root_operation, [user['id'], root])
		returnValue(True)
	
	@inlineCallbacks
	def removeUserRoots(self, user, root_ids):
		"""
		Remove these roots for this user.
		
		@param user: the current user
		@type user: L{txopenid.user.User}
		
		@param identity_ids: a list of IDs to remove
		@type identity_ids: int or list(int)
		
		@return: True if there were no errors.
		"""
		if not(isinstance(root_ids, (list, tuple))):
			root_ids = [root_ids]
		root_operation = "DELETE FROM trusted_root WHERE user_id = %%s AND id IN (%s)" % ','.join(['%s']*len(root_ids))
		yield self.conn.runOperation(root_operation, [user['id']] + root_ids)
		returnValue(True)
	
	@inlineCallbacks
	def loadUser(self, user_id):
		"""
		Return the user object for this user_id.
		
		@param user_id: the user ID to load.
		@type user_id: int
		"""
		user_query = "SELECT * FROM user u WHERE u.id = %s"
		result = yield self.conn.runQuery(user_query, [user_id])
		if(result):
			from txopenid import user
			if(result[0]):
				u = user.User(result[0])
				u.pool = self
				returnValue(u)
		returnValue(None)
	
	@inlineCallbacks
	def loadSession(self, sid):
		"""
		Return the session record for this user_id.
		
		@param user_id: the user ID to load.
		@type user_id: int
		
		@return: the session record
		@rtype: L{dict}
		"""
		session_query = "SELECT * FROM session s WHERE s.id = %s"
		result = yield self.conn.runQuery(session_query, [sid])
		if(result):
			returnValue(result[0])
		returnValue(None)
	
	@inlineCallbacks
	def saveSession(self, session):
		"""
		Save the provided session record.
		
		@param session: the session record to save
		@type session: dict
		
		@return: True if there were no errors.
		"""
		if(session.get('_new') is None):
			fields = []
			values = []
			for column, value in session.items():
				if(column != 'id'):
					fields.append('%s = %%s' % column)
					values.append(value)
			values.append(session['id'])
			save_query = "UPDATE session SET %s WHERE id = %%s" % ', '.join(fields)
		else:
			del session['_new']
			keys = session.keys()
			values = session.values()
			save_query = "INSERT INTO session (%s) VALUES (%s)" % (', '.join(keys), ', '.join(['%s'] * len(values)))
		
		yield self.conn.runOperation(save_query, values)
		returnValue(True)
	
	@inlineCallbacks
	def verifyLogin(self, username, password):
		"""
		Get the user_id for the provided username and password.
		
		@param username: the login username
		@type username: str
		
		@param password: the login password
		@type password: str
		
		@return: the user_id, or None
		@rtype: int
		"""
		session_query = "SELECT id FROM user u WHERE u.username = %s AND u.crypt = ENCRYPT(%s, SUBSTRING(u.crypt, 1, 2))"
		result = yield self.conn.runQuery(session_query, [username, password])
		if(result):
			returnValue(result[0]['id'])
		returnValue(None)
	
	@inlineCallbacks
	def verifySession(self, sid):
		"""
		Get the user_id for the provided session ID.
		
		@param sid: the login session ID
		@type sid: str
		
		@return: the user_id, or None
		@rtype: int
		"""
		session_query = "SELECT * FROM session s WHERE s.id = %s AND accessed - created < timeout"
		result = yield self.conn.runQuery(session_query, [sid])
		if(result):
			returnValue(result[0]['user_id'])
		returnValue(None)
	
	def destroySession(self, sid):
		"""
		Remove expired sessions from the database.
		"""
		destroy_query = "DELETE FROM session WHERE id = %s"
		return self.conn.runOperation(destroy_query, [sid])
	
	def cleanupSessions(self):
		"""
		Remove expired sessions from the database.
		"""
		cleanup_query = "DELETE FROM session WHERE timeout < (%s - accessed)"
		return self.conn.runOperation(cleanup_query, [int(time.time())])