# txopenid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

"""
OpenID Specification support.

This module contains handlers for all the major functions of an OpenID request.

Spec Page::
    L{http://openid.net/specs/openid-authentication-1_1.html}

Test Page::
    L{http://www.openidenabled.com/resources/openid-test/diagnose-server}


@var OPENID_PROVIDER_URL: OpenID queries will be sent here
@var OPENID_LOGIN_URL: User login page, redirects to info page when already logged in.
@var OPENID_IDENTITY_URL: Add/remove OpenID identities.
@var OPENID_TRUST_URL: Add/remove OpenID trusted roots.
@var OPENID_INFO_URL: Overview of user account, redirects to login page when necessary.
"""

import base64, urllib, time

from twisted.python import log
from twisted.internet.defer import inlineCallbacks, returnValue, maybeDeferred

from nevow.url import URL

from txopenid import util

OPENID_PROVIDER_URL = 'http://%s/'
OPENID_LOGIN_URL = 'http://%s/user/login'
OPENID_IDENTITY_URL = 'http://%s/user/identity'
OPENID_TRUST_URL = 'http://%s/user/trust'
OPENID_INFO_URL = 'http://%s/user/info'

DH_SHA1_ENABLED = False

DH_P_VALUE = int('155172898181473697471232257763715539915724801966915404479707795'
				'314057629378541917580651227423698188993727816152646631438561595'
				'825688188889951272158842675419950341258706556549803580104870537'
				'681476726513255747040765857479291291572334510643245094715007229'
				'621094194349783925984760375594985848253359305585439638443')

def configure_urls(hostname, port=80):
	"""
	Replace the placeholders in the various URL types with the current hostname.
	
	@param hostname: The hostname to use in return URLs.
	@type hostname: str
	
	@param port: The port to use in return URLs
	@type port: int
	"""
	host = hostname
	if(int(port) != 80):
		host += ':' + str(port)
	
	global OPENID_PROVIDER_URL
	OPENID_PROVIDER_URL = OPENID_PROVIDER_URL % host
	
	global OPENID_LOGIN_URL
	OPENID_LOGIN_URL = OPENID_LOGIN_URL % host
	
	global OPENID_IDENTITY_URL
	OPENID_IDENTITY_URL = OPENID_IDENTITY_URL % host
	
	global OPENID_TRUST_URL
	OPENID_TRUST_URL = OPENID_TRUST_URL % host
	
	global OPENID_INFO_URL
	OPENID_INFO_URL = OPENID_INFO_URL % host

def associate(registry, requestData):
	"""
	An ID Consumer wants to establish a shared secret.
	
	@param registry: the current OpenID registry
	@type registry: L{OpenIDRegistry}
	
	@param requestData: the current request data
	@type requestData: L{OpenIDRequest}
	
	@return: association response
	@rtype: str or L{nevow.url.URL}
	"""
	association = registry.initiate(requestData, True)
	response = dict(
		assoc_type		= association.assoc_type,
		assoc_handle	= association.handle,
		expires_in		= association.expires_in
	)
	
	if(DH_SHA1_ENABLED and requestData.get('openid.session_type') == 'DH-SHA1'):
		response['enc_mac_key'] = association.enc_mac_key
	else:
		response['mac_key'] = association.mac_key
	
	log.msg('[associate] new consumer association, dict: %r' % association.__dict__);
	return util.kvstr(**response)

@inlineCallbacks
def checkid_immediate(registry, requestData, user=None):
	"""
	Validate the provided request.
	
	@param registry: the current OpenID registry
	@type registry: L{OpenIDRegistry}
	
	@param requestData: the current request data
	@type requestData: L{OpenIDRequest}
	
	@param user: the current user
	@type user: L{txopenid.user.User}
	
	@return: checkid response
	@rtype: L{nevow.url.URL}
	"""
	if(user is not None):
		def _identity_state():
			return user.hasIdentity(requestData['openid.identity'])
		
		def _trust_state():
			 return user.trustsRoot(requestData['openid.trust_root'])
		
		if not(yield maybeDeferred(_identity_state)):
			return_to = util.appendQuery(requestData['openid.return_to'], {
				'openid.mode':'id_res', 
				'openid.user_setup_url':util.appendQuery(OPENID_IDENTITY_URL, requestData),
			})
		elif not(yield maybeDeferred(_trust_state)):
			return_to = util.appendQuery(requestData['openid.return_to'], {
				'openid.mode':'id_res', 
				'openid.user_setup_url':util.appendQuery(OPENID_TRUST_URL, requestData),
			})
		else:
			return_to = get_login_response(registry, requestData)
	else:
		return_to = util.appendQuery(requestData['openid.return_to'], {
			'openid.mode':'id_res', 
			'openid.user_setup_url':util.appendQuery(OPENID_LOGIN_URL, requestData),
		})
	returnValue(URL.fromString(return_to))

@inlineCallbacks
def checkid_setup(registry, requestData, user=None):
	"""
	This method will validate and redirect a successful request to its
	return_to param. If the user isn't logged in, or doesn't have an account,
	we'll redirect to an internal page.
	
	@param registry: the current OpenID registry
	@type registry: L{OpenIDRegistry}
	
	@param requestData: the current request data
	@type requestData: L{OpenIDRequest}
	
	@param user: the current user
	@type user: L{txopenid.user.User}
	
	@return: association response
	@rtype: L{nevow.url.URL}
	"""
	if(user is not None):
		def _identity_state():
			return user.hasIdentity(requestData['openid.identity'])
		
		def _trust_state():
			 return user.trustsRoot(requestData['openid.trust_root'])
		
		if not(yield maybeDeferred(_identity_state)):
			return_to = util.appendQuery(OPENID_IDENTITY_URL, requestData)
		elif not(yield maybeDeferred(_trust_state)):
			return_to = util.appendQuery(OPENID_TRUST_URL, requestData)
		else:
			return_to = get_login_response(registry, requestData)
	else:
		return_to = util.appendQuery(OPENID_LOGIN_URL, requestData)
	
	returnValue(URL.fromString(return_to))

def get_login_response(registry, requestData):
	"""
	Convenience function to return a valid login response for the provided request.

	@param registry: the current OpenID registry
	@type registry: L{OpenIDRegistry}
	
	@param requestData: the current request data
	@type requestData: L{OpenIDRequest}
	
	@return: a response URL
	@rtype: str
	"""
	log.msg('[get_login_response] request: %r' % requestData)
	
	association = registry.initiate(requestData, 'openid.assoc_handle' in requestData)
	log.msg('[get_login_response] association: %r' % association)
	
	log.msg('[get_login_response] Using handle: %r' % association.handle)
	token_key = util.secret(association.handle)
	log.msg('[get_login_response] Found key: %r' % token_key)
	token_contents = util.kvstr(
		mode		= 'id_res',
		identity	= requestData['openid.identity'],
		return_to	= requestData['openid.return_to'],
	)
	
	return_dict = {
		'openid.mode'			: 'id_res',
		'openid.identity'		: requestData['openid.identity'],
		'openid.assoc_handle'	: association.handle,
		'openid.return_to'		: requestData['openid.return_to'],
		'openid.signed'			: 'identity,mode,return_to',
		'openid.sig'			: base64.b64encode(util.get_hmac(token_key, token_contents))
	}
	
	if(association.handle != requestData.get('openid.assoc_handle', association.handle)):
		log.msg("[get_login_response] Retrieved association handle doesn't match request: %r" % requestData['openid.assoc_handle'])
		return_dict['openid.invalidate_handle'] = requestData['openid.assoc_handle']
	
	return util.appendQuery(requestData['openid.return_to'], return_dict)

def check_authentication(registry, requestData):
	"""
	Verify authentication for a previous "dumb" request.
	
	@param registry: the current OpenID registry
	@type registry: L{OpenIDRegistry}
	
	@param requestData: the current request data
	@type requestData: L{OpenIDRequest}
	
	@return: authentication response
	@rtype: str
	"""
	valid_string = repr(registry.validate(requestData, False)).lower()
	association = registry.initiate(requestData, False)
	
	log.msg('[check_authentication] request: %r' % requestData)
	log.msg('[check_authentication] association: %r' % association)
	if(association.handle == requestData['openid.assoc_handle']):
		output = util.kvstr({'openid.mode':'id_res'}, is_valid=valid_string)
	else:
		output = util.kvstr({'openid.mode':'id_res'}, is_valid=valid_string, invalidate_handle=requestData['openid.assoc_handle'])
	
	log.msg('[check_authentication] returning: %r' % output)
	
	return output

class OpenIDRegistry(object):
	"""
	A holding area for shared secrets.
	"""
	def __init__(self):
		"""
		Create a new OpenID shared secret registry.
		"""
		self.smart = {}
		self.dumb = {}
	
	def initiate(self, requestData, is_smart):
		"""
		Load or create the openid association, and return the association object.
		
		@param requestData: the current request
		@type requestData: L{OpenIDRequest}
		
		@param is_smart: if False, create a new association handle for this response
		
		@return: the associated association
		@rtype: L{OpenIDAssociation}
		"""
		if('openid.assoc_type' in requestData):
			assoc_type = requestData['openid.assoc_type']
		else:
			assoc_type = 'HMAC-SHA1'
		
		# TODO: i think this section also needs to check expiry dates
		# on shared secrets, returning new association handles if
		# appropriate.
		handle = requestData.get('openid.assoc_handle', None)
		
		if(is_smart):
			log.msg('Trying to find smart association')
			bank = self.smart
		else:
			log.msg('Trying to find dumb association')
			bank = self.dumb
		
		if(handle in bank):
			log.msg('    found handle: %r' % handle)
			association = bank[handle]
			if(time.time() - association.created > association.expires_in):
				log.msg('    association expired, returning new')
				del bank[association.handle]
				association = OpenIDAssociation(requestData, assoc_type)
				bank[association.handle] = association
		else:
			association = OpenIDAssociation(requestData, assoc_type)
			bank[association.handle] = association
			log.msg('    saved handle: %r' % association.handle)
		
		log.msg('    association: %r' % association)
		
		return association
	
	def validate(self, requestData, is_smart):
		"""
		Take the hashed "sig" that was passed in the request
		and compare it to one we generate using the key we
		believe belongs to the consumer.
		
		@param requestData: the current request
		@type requestData: L{OpenIDRequest}
		
		@param is_smart: if False, create a new association handle for this response
		
		@return: True if the request is valid.
		"""
		handle = requestData['openid.assoc_handle']
		
		if(is_smart):
			log.msg('Validating smart association')
			bank = self.smart
		else:
			log.msg('Validating dumb association')
			bank = self.dumb
		
		if(handle in bank):
			log.msg('    found handle: %r' % handle)
			association = bank[handle]
			log.msg('    association: %r' % association)
			if(time.time() - association.created > association.expires_in):
				log.msg('    association expired, denying handle')
				del bank[association.handle]
				return False
		else:
			log.msg('    denied handle: %r' % handle)
			return False
		
		token_contents = util.kvstr(mode='id_res',
								identity=requestData['openid.identity'],
								return_to=requestData['openid.return_to'])
		
		valid_sig = base64.b64encode(util.get_hmac(association.secret, token_contents))
		
		log.msg('Comparing %r' % requestData['openid.sig'])
		log.msg('to valid  %r' % valid_sig)
		
		return requestData['openid.sig'] == valid_sig

class OpenIDAssociation(object):
	"""
	A convenience object that creates keys and the like
	for us when passed a request dictionary.
	"""
	def __init__(self, requestData, assoc_type='HMAC-SHA1', handle=None):
		"""
		Create a new association with the provided requestData.
		"""
		if(handle):
			self.handle = handle
		else:
			self.handle = base64.b64encode(util.handle())
		
		self.assoc_type = assoc_type
		self.secret = util.secret(self.handle, assoc_type)
		self.created = time.time()
		self.expires_in = '86400'
		
		if(DH_SHA1_ENABLED and requestData.get('openid.session_type') == 'DH-SHA1'):
			self.dh_modulus = util.mklong(base64.b64decode(requestData['openid.dh_modulus']))
			self.dh_gen = util.mklong(base64.b64decode(requestData['openid.dh_gen']))
			self.dh_consumer_public = util.mklong(base64.b64decode(requestData['openid.dh_consumer_public']))
			self.dh_server_private = util.mkkey()
			self.dh_server_public = base64.b64encode(util.btwoc(pow(self.dh_gen, self.dh_server_private) % self.dh_modulus))
			self.dh_shared_secret = pow(self.dh_consumer_public, self.dh_server_private) % self.dh_modulus
			self.enc_mac_key = util.secret(util.btwoc(self.dh_shared_secret), 'HMAC-SHA1') ^ self.secret
		else:
			self.mac_key = base64.b64encode(self.secret)
	
	def __repr__(self):
		return str(self.__dict__)

class OpenIDRequest(dict):
	"""
	A wrapper class for NevowRequest objects.
	"""
	
	def __init__(self, request):
		"""
		Take the provided Nevow request and extract
		the parameters from the GET and or POST data.
	
		OpenID params are pretty simple, so we don't
		worry about having multiple GET params of the
		same name, or complex POST values.
		"""
		if(getattr(request, 'args', None)):
			for key in request.args:
				self[key] = request.args[key][0]
		if(getattr(request, 'fields', None)):
			for key in request.fields:
				self[key] = request.fields[key].value
		
		self.request = request
	
	def clear_request(self):
		"""
		Clear out any existing POST or GET data.
		
		This allows us to take some shortcuts after parsing form data.
		"""
		self.request.args = {}
		self.request.fields = {}
