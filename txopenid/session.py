# txopenid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

"""
Database-resident web session support.

Notes About "Infant" Sessions:

Sessions will not be persisted to disk until a second request is made
providing the session cookie. Until that time, they are kept in the
INFANT_SESSIONS dict. This table could get rather large, since OpenID
consumers don't really have to be cookie-aware, and their requests may
end up creating numerous fake sessions. It could be neccessary to purge
the infant session cache more frequently than the relational db.

Another option for dealing with this is to simply not save the session
unless a user_id is being set, because in our case that means the user
must support cookies. I'd rather this session code be more generally
useful, though, and I like the idea of sessions for anonymous users.

If, on the other hand, you'd rather just leave everything in the DB,
or are running multiple OpenID servers from the same DB, you probably
will want to set QUARANTINE_INFANT_SESSIONS to False.

@var COOKIE_KEY: the session cookie name
@type COOKIE_KEY: str

@var CLEANUP_CHANCE: the odds that old sessions will be cleanup during this request
@type CLEANUP_CHANCE: int

@var QUARANTINE_INFANT_SESSIONS: should new sessions be quarantined until they are used a second time?
@type QUARANTINE_INFANT_SESSIONS: bool

@var INFANT_SESSIONS: holding area for new sessions
@type INFANT_SESSIONS: dict(str => dict)

@var INFANT_SESSION_TIMEOUT: if a session hasn't been verified in this long, remove it
@type INFANT_SESSION_TIMEOUT: int
"""

import time, md5, random, os, thread, threading

from zope.interface import implements

from twisted.python import log
from twisted.internet.defer import inlineCallbacks, returnValue, maybeDeferred, Deferred
from twisted.cred import portal, checkers, credentials

from nevow import inevow, rend

from txopenid import db

COOKIE_KEY = 'sid'
CLEANUP_CHANCE = 100

QUARANTINE_INFANT_SESSIONS = True
INFANT_SESSIONS = {}
INFANT_SESSION_TIMEOUT = 3600

def createSessionCookie(request):
	"""
	Make a number based on current time, pid, remote ip
	and two random ints, then hash with md5. This should
	be fairly unique and very difficult to guess.
	"""
	t = long(time.time()*10000)
	pid = os.getpid()
	rnd1 = random.randint(0, 999999999)
	rnd2 = random.randint(0, 999999999)
	ip = request.getClientIP()
	
	return md5.new("%d%d%d%d%s" % (t, pid, rnd1, rnd2, ip)).hexdigest()

@inlineCallbacks
def destroySession(pool, request):
	"""
	Destroy the current session for this request.
	
	Delete the session record and remove the session cookie.
	"""
	sid = request.getCookie(COOKIE_KEY)
	if(sid):
		date = time.strftime("%a, %d-%b-%Y %H:%M:%S GMT", time.gmtime(time.time() - 86400))
		request.addCookie(COOKIE_KEY, '', path='/', expires=date)
		yield pool.destroySession(sid)
	
	returnValue(None)

@inlineCallbacks
def updateSession(pool, request, user=None):
	"""
	Update the access time and/or user_id for this session.
	
	This function will first attempt to find the session in the infant
	session cache, removing it (and saving it to DB) if found.
	
	updateSession is also responsible for setting the session cookie
	if it doesn't yet exist.
	
	@param pool: the database connection to use.
	@type pool: L{txopenid.db.Connection}
	
	@param request: the current request.
	@type request: L{nevow.appserver.NevowRequest}
	
	@param user: the current user, if any
	@type user: L{txopenid.user.User}
	"""
	sid = request.getCookie(COOKIE_KEY)
	if not(sid):
		sid = createSessionCookie(request)
		request.addCookie(COOKIE_KEY, sid, path='/')
	
	if(sid in INFANT_SESSIONS):
		session = INFANT_SESSIONS[sid]
		del INFANT_SESSIONS[sid]
	else:
		session = yield pool.loadSession(sid)
	
	if(session and session['accessed'] - session['created'] > session['timeout']):
		destroySession(pool, request)
		sid = createSessionCookie(request)
		request.addCookie(COOKIE_KEY, sid, path='/')
		user = None
		session = None
	
	if not(session):
		session = dict(
			id = sid,
			user_id = 0,
			created = int(time.time()),
			timeout = 3600,
			data = None,
			_new = True
		)
		if(QUARANTINE_INFANT_SESSIONS):
			INFANT_SESSIONS[sid] = session
	
	session['accessed'] = int(time.time())
	if(user and user['id']):
		session['user_id'] = user['id']
	
	if(sid not in INFANT_SESSIONS):
		yield pool.saveSession(session)
	
	if(random.randint(1, CLEANUP_CHANCE) == 1):
		_cleanupInfantSessions()
		log.msg('Expiring abandoned sessions')
		pool.cleanupSessions()

def getSessionCredentials(ctx):
	"""
	Given a Nevow context object, return a SessionCredentials object.
	
	@param ctx: the current context
	@type ctx: L{nevow.context.WebContext}
	
	@return: the session credentials
	@rtype: L{SessionCredentials} or L{twisted.cred.credentials.Anonymous}
	"""
	request = inevow.IRequest(ctx)
	cookie = request.getCookie(COOKIE_KEY)
	if(cookie):
		creds = SessionCredentials(cookie)
	else:
		creds = credentials.Anonymous()
	return creds

def _cleanupInfantSessions():
	"""
	Iterate through the infant session cache and remove expired sessions.
	"""
	for sid, session in INFANT_SESSIONS.items():
		if(time.time() - session['created'] > INFANT_SESSION_TIMEOUT):
			log.msg('Expiring infant session %s' % sid)
			del INFANT_SESSIONS[sid]

class SessionRealm(object):
	"""
	This Realm holds our OpenIDRegistry object, and will
	choose the appropriate delegate Resource to reflect
	the authentication state.

	@ivar pool: the current database connection
	@type pool: L{txopenid.db.Connection}
	
	@ivar registry: the current OpenID registry
	@type registry: L{txopenid.protocol.OpenIDRegistry}
	"""
	implements(portal.IRealm)
	
	def __init__(self, pool, registry):
		"""
		Create a new realm that can authenticate against the provided db pool.
		
		The association registry is kept here for now, but ultimately it may
		be replaced by direct database access.
		
		@param pool: the current database connection
		@type pool: L{txopenid.db.Connection}
		
		@param registry: the current OpenID registry
		@type registry: L{txopenid.protocol.OpenIDRegistry}
		"""
		self.pool = pool
		self.registry = registry
	
	@inlineCallbacks
	def requestAvatar(self, avatarId, mind, *interfaces):
		"""
		@see: L{twisted.cred.portal.IRealm}
		
		@param avatarId: the authenticated user ID, or L{twisted.cred.checkers.ANONYMOUS}
		"""
		if inevow.IResource not in interfaces:
			raise NotImplementedError("no appropriate interface found")
		
		user = None
		if avatarId is not checkers.ANONYMOUS:
			user = yield self.pool.loadUser(avatarId)
		
		returnValue((inevow.IResource, user, lambda: None))

class ISessionCredentials(credentials.ICredentials):
	"""
	I represent an opaque value indicating a web session.
	"""
	def getSid(self):
		"""
		Return the session ID for these credentials.
		
		@return: the session ID
		@rtype: str
		"""
		pass

class SessionCredentials(object):
	"""
	An opaque value indicating a web session.
	"""
	implements(ISessionCredentials)

	def __init__(self, sid):
		"""
		Create a new credentials object with the provided session ID.
		
		@param sid: current session id
		"""
		self.sid = sid

	def getSid(self):
		"""
		Get the session id for these credentials.
		
		@return: the session ID
		@rtype: str
		"""
		return self.sid

class SessionChecker(object):
	"""
	Validator for web logins.
	
	A SessionChecker can handle a number of types of credentials,
	including ISessionCredentials, IUsernamePassword, and IAnonymous.
	"""
	implements(checkers.ICredentialsChecker)
	
	credentialInterfaces = (ISessionCredentials,
							credentials.IUsernamePassword,
							credentials.IAnonymous)
	
	def __init__(self, pool):
		self.pool = pool
	
	def requestAvatarId(self, creds):
		"""
		@see: L{twisted.cred.checkers.ICredentialsChecker}
		"""
		if(ISessionCredentials.providedBy(creds)):
			return self.checkSessionCredentials(creds)
		elif(credentials.IUsernamePassword.providedBy(creds)):
			return self.checkLoginCredentials(creds)
		else:
			d = Deferred()
			d.callback(checkers.ANONYMOUS)
			return d
	
	@inlineCallbacks
	def checkSessionCredentials(self, creds):
		"""
		Return the user_id assigned to the provided session credentials.
		
		@param creds: the current session's credentials.
		@type creds: L{ISessionCredentials}
		
		@return: user_id of the authenticated user
		@rtype: int
		"""
		sid = creds.getSid()
		if(sid in INFANT_SESSIONS):
			returnValue(INFANT_SESSIONS[sid]['user_id'])
		
		result = yield self.pool.verifySession(sid)
		if(result):
			returnValue(result)
		else:
			returnValue(checkers.ANONYMOUS)
	
	@inlineCallbacks
	def checkLoginCredentials(self, creds):
		"""
		Return the user_id assigned to the provided session credentials.
		
		@param creds: the current session's credentials.
		@type creds: L{twisted.cred.checkers.IUsernamePassword}
		
		@return: user_id of the authenticated user
		@rtype: int
		"""
		result = yield self.pool.verifyLogin(creds.username, creds.password)
		if(result):
			returnValue(result)
		else:
			returnValue(checkers.ANONYMOUS)
