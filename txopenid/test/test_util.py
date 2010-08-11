# txopenid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

"""
Test util module.
"""

import sha, cgi

from twisted.trial import unittest

from txopenid import util, protocol

class UtilityTestCase(unittest.TestCase):
	def setUp(self):
		pass
	
	def tearDown(self):
		pass
	
	def test_btwoc(self):
		value = 1212602127
		expected = 'HF\xd7\x0f'
		got = util.btwoc(value)
		self.failUnlessEqual(got, expected, "Got %r when expecting %r" % (got, expected))
	
	def test_mklong(self):
		value = 'HF\xd7\x0f'
		expected = 1212602127
		got = util.mklong(value)
		self.failUnlessEqual(got, expected, "Got %r when expecting %r" % (got, expected))
	
	def test_mkkey(self):
		got = util.mkkey()
		self.failUnlessEqual(len(str(got)), 100)
	
	def test_secret_sha1(self):
		value = 'some string'
		expected = '\x8bE\xe4\xbd\x1cj\xcb\x88\xbe\xbfd\x07\xd1b\x05\xf5g\xe6*>'
		got = util.secret(value)
		self.failUnlessEqual(got, expected, "Got %r when expecting %r" % (got, expected))
	
	def test_secret_invalid(self):
		self.failUnlessRaises(NotImplementedError, util.secret, 'some string', 'otherhashmethod')
	
	def test_get_hmac(self):
		key = 'some key'
		message = 'some message'
		expected = '\x01P]/\xc3]\x00\xb3c[\xf7\x92^\xba]\t\x03\x1b3\xf1'
		got = util.get_hmac(key, message)
		self.failUnlessEqual(got, expected, "Got %r when expecting %r" % (got, expected))
	
	def test_handle(self):
		h = util.handle()
		
		self.failUnlessEqual(len(h), 64)
		for c in h:
			if(ord(c) < 0 or ord(c) > 255):
				self.fail('Found invalid character in handle string.')
	
	def test_kvstr(self):
		value = dict(
			one		= 1,
			two		= 2,
			three	= 3,
		)
		expected = 'one:1\nthree:3\ntwo:2\n'
		got = util.kvstr(**value)
		self.failUnlessEqual(got, expected, "Got %r when expecting %r" % (got, expected))
	
	def test_appendQuery_base(self):
		return_to = 'http://www.example.com'
		error = dict(error='some error occurred')
		expected = 'http://www.example.com/?error=some+error+occurred'
		got = util.appendQuery(return_to, error)
		self.failUnlessEqual(got, expected, "Got %r when expecting %r" % (got, expected))
	
	def test_appendQuery_path(self):
		return_to = 'http://www.example.com/some/path'
		error = dict(error='some error occurred')
		expected = 'http://www.example.com/some/path?error=some+error+occurred'
		got = util.appendQuery(return_to, error)
		self.failUnlessEqual(got, expected, "Got %r when expecting %r" % (got, expected))
	
	def test_appendQuery_slash(self):
		return_to = 'http://www.example.com/some/path/'
		error = dict(error='some error occurred')
		expected = 'http://www.example.com/some/path/?error=some+error+occurred'
		got = util.appendQuery(return_to, error)
		self.failUnlessEqual(got, expected, "Got %r when expecting %r" % (got, expected))
