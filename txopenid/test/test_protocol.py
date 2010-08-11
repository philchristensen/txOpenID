# txopenid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

"""
Test protocol module.
"""

import sha, cgi, base64, urllib

from twisted.trial import unittest
from twisted.internet.defer import inlineCallbacks, returnValue

from nevow import url

from txopenid import util, protocol
from txopenid.test import TestUser

test_handle = '72LSndh2ZN9VKt08GRPA6NaAEp0tTG2Puxq5vGnrqVkF2iRPl001s1DXL9t+y6Gik8QswcPEZ6rlZymoHFHkpw=='

class TestRegistry(object):
	def __init__(self, handle=None, validation=True):
		self.handle = handle
		self.validation = validation
	
	def initiate(self, requestData, smart):
		if(self.handle):
			association = protocol.OpenIDAssociation(requestData, handle=self.handle)
		else:
			association = protocol.OpenIDAssociation(requestData)
		return association
	
	def validate(self, requestData, is_smart):
		return self.validation

class TestRequest(dict):
	def __init__(self, data, method='GET'):
		self.update(data)
		self.request = TestNevowRequest()
		self.request.method = method

class TestNevowRequest(object):
	def __init__(self, args=None, fields=None):
		self.args = {}
		self.fields = {}
		
		if(args is not None):
			for k, v in args.items():
				self.args.setdefault(k, []).append(v)
		
		if(fields is not None):
			for k, v in fields.items():
				self.fields[k] = cgi.MiniFieldStorage(k, v)
	
	def setResponseCode(self, responseCode):
		self.responseCode = responseCode

class ProtocolTestCase(unittest.TestCase):
	def setUp(self):
		pass
	
	def tearDown(self):
		pass
	
	def test_associate(self):
		registry = TestRegistry(test_handle)
		result = protocol.associate(registry, {})
		
		expecting = 'assoc_handle:72LSndh2ZN9VKt08GRPA6NaAEp0tTG2Puxq5vGnrqVk'
		expecting += 'F2iRPl001s1DXL9t+y6Gik8QswcPEZ6rlZymoHFHkpw==\n'
		expecting += 'assoc_type:HMAC-SHA1\nexpires_in:86400\n'
		expecting += 'mac_key:y/NsSugej//MGmCmUyauWLSlZKM=\n'
		
		self.failUnlessEqual(result, expecting)
	
	@inlineCallbacks
	def test_checkid_immediate_passes(self):
		registry = TestRegistry(test_handle)
		result = yield protocol.checkid_immediate(registry, TestRequest({
			'openid.mode'			: 'checkid_immediate',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.trust_root'		: 'http://www.example.com/trust',
		}), user=TestUser())
		
		expecting_dict = {
			'openid.mode'			: 'id_res',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.sig'			: 'HDvMdCLdF2UNw02pRurQWowEK84=',
			'openid.signed'			: 'identity,mode,return_to',
		}
		
		expecting = 'http://www.example.com/return?%s' % urllib.urlencode(expecting_dict)
		
		self.failUnless(isinstance(result, url.URL))
		self.failUnlessEqual(str(result), expecting)
	
	def test_checkid_immediate_login_needed(self):
		return self._test_checkid_setup(protocol.OPENID_LOGIN_URL, None)
	
	def test_checkid_immediate_identity_needed(self):
		return self._test_checkid_setup(protocol.OPENID_IDENTITY_URL, TestUser(identify=False))
	
	def test_checkid_immediate_trust_needed(self):
		return self._test_checkid_setup(protocol.OPENID_TRUST_URL, TestUser(trust=False))
	
	@inlineCallbacks
	def _test_checkid_immediate(self, setup_url, user):
		registry = TestRegistry(test_handle)
		result = yield protocol.checkid_immediate(registry, TestRequest({
			'openid.mode'			: 'checkid_immediate',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.trust_root'		: 'http://www.example.com/trust',
		}), user=user)
		
		expecting_dict = {
			'openid.mode'			: 'id_res',
			'openid.user_setup_url'	: setup_url
		}
		
		expecting = 'http://www.example.com/return?%s' % urllib.urlencode(expecting_dict)
		
		self.failUnless(isinstance(result, url.URL), 'Result was %r' % result)
		self.failUnlessEqual(str(result), expecting)
	
	@inlineCallbacks
	def test_checkid_setup_passes(self):
		registry = TestRegistry(test_handle)
		result = yield protocol.checkid_setup(registry, TestRequest({
			'openid.mode'			: 'checkid_setup',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.trust_root'		: 'http://www.example.com/trust',
		}), user=TestUser())
		
		expecting_dict = {
			'openid.mode'			: 'id_res',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.sig'			: 'HDvMdCLdF2UNw02pRurQWowEK84=',
			'openid.signed'			: 'identity,mode,return_to',
		}
		
		expecting = 'http://www.example.com/return?%s' % urllib.urlencode(expecting_dict)
		
		self.failUnless(isinstance(result, url.URL))
		self.failUnlessEqual(str(result), expecting)
	
	def test_checkid_setup_login_needed(self):
		return self._test_checkid_setup(protocol.OPENID_LOGIN_URL, None)
	
	def test_checkid_setup_identity_needed(self):
		return self._test_checkid_setup(protocol.OPENID_IDENTITY_URL, TestUser(identify=False))
	
	def test_checkid_setup_trust_needed(self):
		return self._test_checkid_setup(protocol.OPENID_TRUST_URL, TestUser(trust=False))
	
	@inlineCallbacks
	def _test_checkid_setup(self, setup_url, user):
		registry = TestRegistry(test_handle)
		result = yield protocol.checkid_setup(registry, TestRequest({
			'openid.mode'			: 'checkid_setup',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.trust_root'		: 'http://www.example.com/trust',
		}), user=user)
		
		expecting_dict = {
			'openid.mode'			: 'checkid_setup',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.trust_root'		: 'http://www.example.com/trust',
		}
		
		expecting = util.appendQuery(setup_url, expecting_dict)
		
		self.failUnless(isinstance(result, url.URL))
		self.failUnlessEqual(str(result), expecting)
	
	def test_get_login_response(self):
		"""
		This test is probably not necessary, since it does most of the work for
		checkid_immediate and checkid_setup during a successful login.
		"""
		
		registry = TestRegistry(test_handle)
		result = protocol.get_login_response(registry, TestRequest({
			'openid.mode'			: 'checkid_immediate',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.trust_root'		: 'http://www.example.com/trust',
		}))
		
		expecting_dict = {
			'openid.mode'			: 'id_res',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.sig'			: 'HDvMdCLdF2UNw02pRurQWowEK84=',
			'openid.signed'			: 'identity,mode,return_to',
		}
		
		expecting = 'http://www.example.com/return?%s' % urllib.urlencode(expecting_dict)
		
		self.failIf(isinstance(result, url.URL))
		self.failUnlessEqual(result, expecting)
	
	def test_authentication_passes(self):
		registry = TestRegistry(test_handle)
		result = protocol.check_authentication(registry, TestRequest({
			'openid.mode'			: 'check_authentication',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
		}))
		
		expecting = 'is_valid:true\nopenid.mode:id_res\n'
		
		self.failUnlessEqual(result, expecting)
	
	def test_authentication_fails(self):
		registry = TestRegistry(test_handle, validation=False)
		result = protocol.check_authentication(registry, TestRequest({
			'openid.mode'			: 'check_authentication',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
		}))
		
		expecting = 'is_valid:false\nopenid.mode:id_res\n'
		
		self.failUnlessEqual(result, expecting)
	
	def test_authentication_passes_invalid(self):
		registry = TestRegistry()
		result = protocol.check_authentication(registry, TestRequest({
			'openid.mode'			: 'check_authentication',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
		}))
		
		expecting = 'invalidate_handle:%s\nis_valid:true\nopenid.mode:id_res\n' % test_handle
		
		self.failUnlessEqual(result, expecting)
	
	def test_authentication_fails_invalid(self):
		registry = TestRegistry(validation=False)
		result = protocol.check_authentication(registry, TestRequest({
			'openid.mode'			: 'check_authentication',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.assoc_handle'	: test_handle,
		}))
		
		expecting = 'invalidate_handle:%s\nis_valid:false\nopenid.mode:id_res\n' % test_handle
		
		self.failUnlessEqual(result, expecting)
	
	def test_OpenIDRequest_GET(self):
		request = TestNevowRequest(args=dict(one='1', two='2', three='3'))
		normalized = protocol.OpenIDRequest(request)
		self.failUnlessEqual(normalized['one'], '1')
	
	def test_OpenIDRequest_POST(self):
		request = TestNevowRequest(fields=dict(one='1', two='2', three='3'))
		normalized = protocol.OpenIDRequest(request)
		self.failUnlessEqual(normalized['three'], '3')
	
	def test_OpenIDRequest_BOTH(self):
		request = TestNevowRequest(args=dict(one='1', two='2', three='3'), fields=dict(four='4', five='5', six='6'))
		normalized = protocol.OpenIDRequest(request)
		self.failUnlessEqual(normalized['two'], '2')
		self.failUnlessEqual(normalized['five'], '5')

class RegistryTestCase(unittest.TestCase):
	def setUp(self):
		pass
	
	def tearDown(self):
		pass
	
	def test_initiate_smart(self):
		self._test_initiate(True)
	
	def test_initiate_dumb(self):
		self._test_initiate(False)
	
	def _test_initiate(self, is_smart):
		registry = protocol.OpenIDRegistry()
		request = TestRequest({
			'openid.mode'			: 'associate',
		})
		if(is_smart):
			request['openid.assoc_handle'] = test_handle
		
		association = registry.initiate(request, is_smart)
		
		if not(association.handle in getattr(registry, ('dumb', 'smart')[is_smart])):
			self.fail("New association not found in registry.")
	
	def test_initiate_expired(self):
		registry = protocol.OpenIDRegistry()
		association = registry.initiate(TestRequest({
			'openid.mode'			: 'associate',
		}), True)
		association.expires_in = -1
		
		if not(association.handle in registry.smart):
			self.fail("First association not found in registry.")
		
		new_association = registry.initiate(TestRequest({
			'openid.mode'			: 'checkid_immediate',
			'openid.assoc_handle'	: association.handle,
		}), True)
		
		self.failIfEqual(association.handle, new_association.handle)
		
		if(association.handle in registry.smart):
			self.fail("Expired association was not removed from registry.")
		
		if not(new_association.handle in registry.smart):
			self.fail("New association not found in registry.")
	
	def test_validate(self):
		registry = protocol.OpenIDRegistry()
		association = registry.initiate(TestRequest({
			'openid.mode'			: 'associate',
		}), True)
		
		token_contents = util.kvstr(mode='id_res',
								identity='http://www.example.com/test',
								return_to='http://www.example.com/return')
		
		valid_sig = base64.b64encode(util.get_hmac(association.secret, token_contents))
		
		result = registry.validate(TestRequest({
			'openid.mode'			: 'associate',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.assoc_handle'	: association.handle,
			'openid.sig'			: valid_sig,
			'openid.signed'			: 'identity,mode,return_to',
		}), True)
		
		if not(result):
			self.fail('Validation failed when it should have passed.')
	
	def test_validate_fails(self):
		registry = protocol.OpenIDRegistry()
		association = registry.initiate(TestRequest({
			'openid.mode'			: 'associate',
		}), True)
		
		result = registry.validate(TestRequest({
			'openid.mode'			: 'checkid_immediate',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.assoc_handle'	: association.handle,
			'openid.sig'			: 'NOT A VALID SIGNATURE',
			'openid.signed'			: 'identity,mode,return_to',
		}), True)
		
		if(result):
			self.fail('Validation passed when it should have failed.')
	
	def test_validate_missing(self):
		registry = protocol.OpenIDRegistry()
		
		result = registry.validate(TestRequest({
			'openid.mode'			: 'checkid_immediate',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.assoc_handle'	: test_handle,
			'openid.sig'			: 'NOT A VALID SIGNATURE',
			'openid.signed'			: 'identity,mode,return_to',
		}), True)
		
		if(result):
			self.fail('Validation passed when it should have failed.')
	
	def test_validate_expired(self):
		registry = protocol.OpenIDRegistry()
		association = registry.initiate(TestRequest({
			'openid.mode'			: 'associate',
		}), True)
		
		token_contents = util.kvstr(mode='id_res',
								identity='http://www.example.com/test',
								return_to='http://www.example.com/return')
		
		valid_sig = base64.b64encode(util.get_hmac(association.secret, token_contents))
		
		result = registry.validate(TestRequest({
			'openid.mode'			: 'checkid_immediate',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.assoc_handle'	: association.handle,
			'openid.sig'			: valid_sig,
			'openid.signed'			: 'identity,mode,return_to',
		}), True)
		
		if not(result):
			self.fail('Validation failed when it should have passed.')
		
		association.expires_in = -1
		
		result = registry.validate(TestRequest({
			'openid.mode'			: 'checkid_immediate',
			'openid.identity'		: 'http://www.example.com/test',
			'openid.return_to'		: 'http://www.example.com/return',
			'openid.assoc_handle'	: association.handle,
			'openid.sig'			: valid_sig,
			'openid.signed'			: 'identity,mode,return_to',
		}), True)
		
		if(result):
			self.fail('Validation passed when it should have failed.')

