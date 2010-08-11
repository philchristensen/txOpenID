# txopenid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

"""
Nevow resources for OpenID support.

These resources provide a connection between the protocol code and the identity
consumer, and allow the end-user to assign trust to particular roots, validate
identities, and perform the inital login.
"""

import os

from zope.interface import implements

from twisted.python import log, failure
from twisted.internet.defer import inlineCallbacks, returnValue, maybeDeferred
from twisted.cred import credentials

from nevow import inevow, rend, loaders, tags, url

from txopenid import assets, util, session, protocol

def get_assets_path(*path):
	"""
	Fetch the path to the given files in the assets directory.
	
	@param *path: path components to join to the assets path.
	
	@return: the full path to the provided asset
	"""
	return os.path.join(os.path.dirname(assets.__file__), *path)

class UserStubPage(rend.Page):
	"""
	Organizational resource, simply redirects to the login page.
	"""
	def renderHTTP(self, ctx):
		request = inevow.IRequest(ctx)
		request.redirect(protocol.OPENID_LOGIN_URL)
		return ''

class LoginPage(rend.Page):
	"""
	The user is redirected to this resource when we need
	to validate their login. Otherwise, the guard.SessionWrapper
	would have returned a ProviderPage.
	"""
	implements(inevow.IResource)
	docFactory = loaders.xmlfile(get_assets_path('login-page.xml'))
	
	def __init__(self, pool, portal):
		"""
		Create a new abstract user page connected to the given pool and portal.
		
		@param pool: the current DB connection
		@type pool: L{txopenid.db.Connection}
		
		@param portal: the current auth portal
		@param portal: L{twisted.cred.portal.Portal}
		"""
		self.pool = pool
		self.portal = portal
	
	@inlineCallbacks
	def renderHTTP(self, ctx):
		"""
		Login form processing, logged-in user and OpenID flow redirect.
		
		@see: L{nevow.inevow.IResource}
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		
		log.msg('UserPage request: %r' % requestData)
		if(requestData.get('submit') == 'cancel'):
			return_to = requestData.get('openid.return_to', protocol.OPENID_LOGIN_URL)
			redirect = util.appendQuery(return_to, {'openid.mode':'cancel'})
			request.redirect(redirect)
			returnValue('')
		elif(requestData.get('submit') == 'login'):
			creds = credentials.UsernamePassword(requestData.get('username', ''),
												 requestData.get('password', ''))
		else:
			creds = session.getSessionCredentials(ctx)
		
		iface, user, logout = yield self.portal.login(creds, None, inevow.IResource)
		
		for k, v in requestData.items():
			if not(k.startswith('openid.')):
				del requestData[k]
		
		yield session.updateSession(self.pool, request, user)
		
		if(user):
			if('openid.mode' in requestData):
				redirect = util.appendQuery(protocol.OPENID_PROVIDER_URL, requestData)
				request.redirect(redirect)
				returnValue('')
			else:
				# This will happen if someone logs in directly, or is already logged in.
				request.redirect(protocol.OPENID_INFO_URL)
				returnValue('')
		
		result = yield maybeDeferred(super(LoginPage, self).renderHTTP, ctx)
		returnValue(result)
	
	def data_openid_fields(self, ctx, data):
		"""
		Template function to replicate openid.* form fields.
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		result = []
		
		for k, v in requestData.items():
			if(k.startswith('openid.')):
				result.append(tags.input(type='hidden', name=k, value=v))
		
		return result
	
	def data_cancel(self, ctx, data):
		"""
		Template function to create a cancel button only during Consumer request.
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		if(requestData.get('openid.mode')):
			return tags.input(type='submit', name='submit', value='cancel')
		return ''

class LogoutPage(rend.Page):
	"""
	A resource to logout the user, and return them to the login page.
	"""
	docFactory = loaders.stan('')
	
	def __init__(self, pool, portal):
		"""
		Create a new abstract user page connected to the given pool and portal.
		
		@param pool: the current DB connection
		@type pool: L{txopenid.db.Connection}
		
		@param portal: the current auth portal
		@param portal: L{twisted.cred.portal.Portal}
		"""
		self.pool = pool
		self.portal = portal
	
	@inlineCallbacks
	def renderHTTP(self, ctx):
		"""
		Remove the session cookie, and delete the session record.
		
		@see: L{nevow.inevow.IResource}
		"""
		request = inevow.IRequest(ctx)
		yield session.destroySession(self.pool, request)
		request.redirect(protocol.OPENID_LOGIN_URL)
		returnValue('')

class AbstractUserPage(rend.Page):
	"""
	All subclasses of this class will have self.user set
	to the currently authenticated user.
	"""
	def __init__(self, pool, portal):
		"""
		Create a new abstract user page connected to the given pool and portal.
		
		@param pool: the current DB connection
		@type pool: L{txopenid.db.Connection}
		
		@param portal: the current auth portal
		@param portal: L{twisted.cred.portal.Portal}
		"""
		self.pool = pool
		self.portal = portal
	
	@inlineCallbacks
	def authenticate(self, ctx):
		"""
		Authenticate the current session.
		"""
		request = inevow.IRequest(ctx)
		
		creds = session.getSessionCredentials(ctx)
		iface, user, logout = yield self.portal.login(creds, None, inevow.IResource)
		yield session.updateSession(self.pool, request, user)
		
		self.user = user
	
	@inlineCallbacks
	def authRedirect(self, ctx):
		"""
		Authenticate the current session, redirecting to login if necessary.
		"""
		yield self.authenticate(ctx)
		if(self.user is None):
			request = inevow.IRequest(ctx)
			request.redirect(protocol.OPENID_LOGIN_URL)
			returnValue(True)
		returnValue(False)
	
class InfoPage(AbstractUserPage):
	"""
	This page displays the details for the connected user.
	"""
	implements(inevow.IResource)
	docFactory = loaders.xmlfile(get_assets_path('info-page.xml'))
	
	@inlineCallbacks
	def renderHTTP(self, ctx):
		result = yield self.authRedirect(ctx)
		if(result):
			returnValue('')
		
		result = yield maybeDeferred(super(InfoPage, self).renderHTTP, ctx)
		returnValue(result)
	
	def data_info(self, ctx, data):
		"""
		Template function to display basic user info.
		"""
		return tags.p()[
			"authorization information for %s (username '%s')." % (
				self.user['first'] + ' ' + self.user['last'],
				self.user['username'],
			)
		]
	
	@inlineCallbacks
	def data_identities(self, ctx, data):
		"""
		Template function to display a list of user identities.
		"""
		result = yield self.user.getIdentities()
		output = [tags.h3()['identities'],
			tags.ul(_class="url-list")[[
				tags.li()[item['url']] for item in result
			]]
		]
		returnValue(output)
	
	@inlineCallbacks
	def data_trusted_roots(self, ctx, data):
		"""
		Template function to display a list of user roots.
		"""
		result = yield self.user.getTrustedRoots()
		output = [tags.h3()['trusted roots'],
			tags.ul(_class="url-list")[[
				tags.li()[item['url']] for item in result
			]]
		]
		returnValue(output)

class IdentityPage(AbstractUserPage):
	"""
	This page displays the details for the connected user.
	"""
	implements(inevow.IResource)
	docFactory = loaders.xmlfile(get_assets_path('identity-page.xml'))
	
	@inlineCallbacks
	def renderHTTP(self, ctx):
		"""
		Identity form processing, OpenID flow redirect.
		
		@see: L{nevow.inevow.IResource}
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		
		result = yield self.authRedirect(ctx)
		if(result):
			returnValue('')
		
		if('submit' in requestData):
			requestData.clear_request()
			if(requestData.get('submit') == 'remove selected'):
				yield self.removeIdent(requestData)
			elif(requestData.get('submit') == 'approve new identity'):
				result = yield self.approveIdent(requestData)
				if(result is not None):
					returnValue(result)
		
		result = yield maybeDeferred(super(IdentityPage, self).renderHTTP, ctx)
		returnValue(result)
	
	@inlineCallbacks
	def removeIdent(self, requestData):
		"""
		Form support to remove selected identities.
		"""
		identity_ids = []
		for k, v in requestData.items():
			if(k.startswith('identity-')):
				junk, identity_id = k.split('-')
				identity_ids.append(identity_id)
		
		yield self.pool.removeUserIdentities(self.user, identity_ids)
		returnValue(None)
	
	@inlineCallbacks
	def approveIdent(self, requestData):
		"""
		Form support to approve specified identity.
		"""
		identity = requestData['openid.identity']
		
		existing_user_id = yield self.pool.getUserIdForIdentity(identity)
		if(existing_user_id):
			if(existing_user_id == self.user['id']):
				raise ValueError('You have already registered that identity.')
			else:
				raise ValueError('Another user has already registered that identity.')
		
		result = yield self.pool.saveUserIdentity(self.user, identity)
		
		if(requestData.get('openid.mode') not in (None, 'checkid_immediate')):
			for k, v in requestData.items():
				if not(k.startswith('openid.')):
					del requestData[k]
			
			return_to = util.appendQuery(protocol.OPENID_PROVIDER_URL, requestData)
			requestData.request.redirect(return_to)
			returnValue('')
		else:
			returnValue(None)
	
	@inlineCallbacks
	def data_identities(self, ctx, data):
		"""
		Template function to display a checkbox list of user identities.
		"""
		result = yield self.user.getIdentities()
		output = [tags.h3()['identities'],
			tags.ul(_class="url-list")[[
				tags.li()[[
					tags.input(type='checkbox', name='identity-%s' % item['id'], value='1'),
					item['url'],
				]]
				for item in result
			]]
		]
		returnValue(output)
	
	def data_new_identity(self, ctx, data):
		"""
		Template function to display the new identity form.
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		current_identity = requestData.get('openid.identity', None)
		if(current_identity):
			return tags.div(_class="trustable")[[
				tags.small()["click 'approve new identity' to verify access to this URL:"],
				tags.br(),
				tags.strong()[current_identity],
				tags.input(type="submit", name="submit", value="approve new identity"),
			]]
		else:
			return tags.div(_class="trustable")[[
				tags.small()["enter a new identity URL here and click 'approve new identity':"],
				tags.br(),
				tags.input(type='text', size="60", name='openid.identity', value=''),
				tags.input(type="submit", name="submit", value="approve new identity"),
			]]
	
	def data_openid_fields(self, ctx, data):
		"""
		Template function to replicate openid.* form fields.
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		result = []
		
		for k, v in requestData.items():
			if(k.startswith('openid.')):
				result.append(tags.input(type='hidden', name=k, value=v))
		
		return result

class TrustPage(AbstractUserPage):
	"""
	This page displays the details for the connected user.
	"""
	implements(inevow.IResource)
	docFactory = loaders.xmlfile(get_assets_path('trust-page.xml'))
	
	@inlineCallbacks
	def renderHTTP(self, ctx):
		"""
		Trusted root form processing, OpenID flow redirect.
		
		@see: L{nevow.inevow.IResource}
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		
		result = yield self.authRedirect(ctx)
		if(result):
			returnValue('')
		
		if('submit' in requestData):
			requestData.clear_request()
			if(requestData.get('submit') == 'remove selected'):
				yield self.removeRoot(requestData)
			elif(requestData.get('submit') == 'approve new root'):
				result = yield self.approveRoot(requestData)
				if(result is not None):
					returnValue(result)
		
		result = yield maybeDeferred(super(TrustPage, self).renderHTTP, ctx)
		returnValue(result)
	
	@inlineCallbacks
	def removeRoot(self, requestData):
		"""
		Form support to remove selected roots.
		"""
		root_ids = []
		for k, v in requestData.items():
			if(k.startswith('root-')):
				junk, root_id = k.split('-')
				root_ids.append(root_id)
		
		yield self.pool.removeUserRoots(self.user, root_ids)
		returnValue(None)
	
	@inlineCallbacks
	def approveRoot(self, requestData):
		"""
		Form support to approve specified root.
		"""
		root = requestData['openid.trust_root']
		result = yield self.pool.saveUserRoot(self.user, root)
		
		if(requestData.get('openid.mode') not in (None, 'checkid_immediate')):
			for k, v in requestData.items():
				if not(k.startswith('openid.')):
					del requestData[k]
			
			return_to = util.appendQuery(protocol.OPENID_PROVIDER_URL, requestData)
			requestData.request.redirect(return_to)
			returnValue('')
		else:
			returnValue(None)
	
	@inlineCallbacks
	def data_trusted_roots(self, ctx, data):
		"""
		Template function to display a checkbox list of user roots.
		"""
		result = yield self.user.getTrustedRoots()
		output = [tags.h3()['trusted roots'],
			tags.ul(_class="url-list")[[
				tags.li()[[
					tags.input(type='checkbox', name='root-%s' % item['id'], value='1'),
					item['url'],
				]]
				for item in result
			]]
		]
		returnValue(output)
	
	def data_new_root(self, ctx, data):
		"""
		Template function to display the new root form.
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		current_root = requestData.get('openid.trust_root', None)
		if(current_root):
			return tags.div(_class="trustable")[[
				tags.small()["click 'approve new root' to verify access to this URL:"],
				tags.br(),
				tags.strong()[current_root],
				tags.input(type="submit", name="submit", value="approve new root"),
			]]
		else:
			return tags.div(_class="trustable")[[
				tags.small()["enter a new root here and click 'approve new root':"],
				tags.br(),
				tags.input(type='text', size="60", name='openid.trust_root', value=''),
				tags.input(type="submit", name="submit", value="approve new root"),
			]]
	
	def data_openid_fields(self, ctx, data):
		"""
		Template function to replicate openid.* form fields.
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		result = []
		
		for k, v in requestData.items():
			if(k.startswith('openid.')):
				result.append(tags.input(type='hidden', name=k, value=v))
		
		return result

class ProviderPage(AbstractUserPage):
	"""
	This resource handles all the interaction with the
	ID Consumer.
	"""
	implements(inevow.IResource)
	
	@inlineCallbacks
	def renderHTTP(self, ctx):
		"""
		OpenID provider flow begins here.
		
		@see: L{nevow.inevow.IResource}
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		
		yield self.authenticate(ctx)
		
		output = False
		try:
			mode = requestData.get('openid.mode')
			registry = self.portal.realm.registry
			if(mode == 'associate'):
				output = protocol.associate(registry, requestData)
			elif(mode == 'checkid_immediate'):
				output = yield protocol.checkid_immediate(registry, requestData, self.user)
			elif(mode == 'checkid_setup'):
				output = yield protocol.checkid_setup(registry, requestData, self.user)
			elif(mode == 'check_authentication'):
				output = protocol.check_authentication(registry, requestData)
			else:
				output = util.handleError(requestData, "invalid mode '%s' specified" % requestData.get('openid.mode'))
		except:
			reason = failure.Failure()
			log.err(reason)
			
			# This should really never happen, since the protocol code itself
			# should attempt to give more informative messages when reasonable
			output = util.handleError(requestData, "A server error occurred: %s" % reason.getErrorMessage())
		
		if(isinstance(output, url.URL)):
			log.msg('REDIRECT: %r' % output)
			request.redirect(output)
			returnValue('')
		else:
			if(output is False):
				returnValue(super(ProviderPage, self).renderHTTP(ctx))
			log.msg('OUTPUT: %r' % output)
			returnValue(output)

class ConsumerPage(AbstractUserPage):
	"""
	This resource allows you to authenticate using an OpenID provider.
	"""
	implements(inevow.IResource)
	docFactory = loaders.xmlfile(get_assets_path('consumer-page.xml'))
	
	@inlineCallbacks
	def renderHTTP(self, ctx):
		"""
		Trusted root form processing, OpenID flow redirect.
		
		@see: L{nevow.inevow.IResource}
		"""
		request = inevow.IRequest(ctx)
		requestData = protocol.OpenIDRequest(request)
		
		yield self.authenticate(ctx)
		
		if('identity' in requestData):
			pass
		
		result = yield maybeDeferred(super(ConsumerPage, self).renderHTTP, ctx)
		returnValue(result)
	
	def data_login_form(self, ctx, data):
		if(self.user):
			result = tags.p()[
				"You have been successfully logged in as %s" % self.user.username
			]
		else:
			result = tags.form(method="POST")[[
				tags.p()['Enter your OpenID identifier to login:'],
				tags.label(_for="openid-field")["id:"],
				tags.input(type="text", size="60", name="identity"),
				tags.input(type="submit", name="submit", value="login"),
			]]
		return result
