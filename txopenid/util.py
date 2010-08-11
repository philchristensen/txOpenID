# txopenid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

"""
OpenID utility functions.
"""

import pickle, random, sha, hmac, urllib

from twisted.python import log

from nevow import url

def btwoc(value):
	"""
	Given some kind of integer (generally a long), this function
	returns the big-endian two's complement as a binary string.
	"""
	l = list(pickle.encode_long(value))
	l.reverse()
	result = ''.join(l)
	log.msg('[bwtwoc] given %r, made %r' % (value, result))
	return result

def mklong(btwoc):
	"""
	Given a big-endian two's complement string, return the
	long int it represents.
	"""
	l = list(btwoc)
	l.reverse()
	result = pickle.decode_long(''.join(l))
	log.msg('[mklong] given %r, made %r' % (btwoc, result))
	return result

def mkkey():
	"""
	Return a random 100-digit number to use as a Diffie-Hellman
	key value.
	"""
	start = int('1' + ('0' * 99))
	end = int('9' * 100)
	return random.randint(start, end)

def secret(assoc_handle, assoc_type='HMAC-SHA1'):
	"""
	Take the given handle and create a secret using the
	given hash type. OpenID 1.1 doesn't support anything
	but SHA1 at this time, so this is a pretty simple
	function.
	"""
	if(assoc_type == 'HMAC-SHA1'):
		result = sha.new(assoc_handle).digest()
		log.msg('[secret] given %r, made %r' % (assoc_handle, result))
		return result
	raise NotImplementedError("invalid assoc_handle type: %s" % assoc_type)

def get_hmac(key, message):
	"""
	Encrypt the given message with the specified key.
	"""
	result = hmac.new(key, message, sha).digest()
	log.msg('[hmac] given %r for %r, made %r' % (key, message, result))
	return result

def handle():
	"""
	Generate a random 8-bit string.
	"""
	result = ''
	for i in range(64):
		result += chr(random.randint(0,255))
	return result

def kvstr(data=None, **kwargs):
	"""
	Take the provided keyword arguments and return
	a newline-separated list of key-value pairs
	"""
	if(data is None):
		data = {}
	data.update(kwargs)
	
	keys = data.keys()
	keys.sort()
	return ''.join(['%s:%s\n' % (x, data[x]) for x in keys])

def handleError(requestData, error):
	"""
	Given some error during the provided request, generate the proper response format.
	"""
	if(requestData.request.method == 'GET'):
		if('openid.return_to' in requestData):
			redirect_dict = {
				'openid.mode'	: 'error',
				'openid.error'	: error
			}
			output = url.URL.fromString(appendQuery(requestData['openid.return_to'], redirect_dict))
		elif(requestData):
			requestData.request.setResponseCode(400)
			output = kvstr(error="A server error occurred: %s" % error)
		# an empty GET
		else:
			output = 'This is an OpenID server endpoint. For more information, see http://openid.net'
	else:
		requestData.request.setResponseCode(400)
		output = kvstr(error="A server error occurred: %s" % error)
	return output

def appendQuery(url, params):
	"""
	Safely append the provided params dict to the given URL.
	"""
	if(url.find('?') == -1):
		slashcount = 0
		if(url.find('://')):
			slashcount = 2
		if(url.count('/') <= slashcount):
			url += '/'
		url += '?'
	else:
		url += '&'
	return url + urllib.urlencode(params)
