#!/usr/bin/env python

# openid
# Copyright (c) 2007 Phil Christensen
#
# See LICENSE for details

from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application import internet, service
from twisted.cred import portal, checkers, credentials

from nevow import appserver, guard, static

from txopenid import session, db, protocol, resource

class Options(usage.Options):
	optParameters = [
						["host", "h", 'localhost', "MySQL server hostname."],
						["port", "p", 3306, "MySQL server port."],
						["name", "n", 'txopenid', "Database name."],
						["username", "u", 'txopenid', "Database username."],
						["secret", "s", 'txopenid', "Database password."],
						["hostname", "H", None, "Hostname to use for txOpenID server URLs."],
						["server-port", "P", 8888, "Port to use for txOpenID server."],
					 	["access-log", "a", '-', "Path to access log."]
					]

class txOpenIDProvider(object):
	implements(service.IServiceMaker, IPlugin)
	tapname = "txopenid-provider"
	description = "Run an OpenID provider."
	options = Options
	
	def makeService(self, config):
		pool = db.Connection(
			host	= config['host'],
			port	= config['port'],
			user	= config['username'],
			passwd	= config['secret'],
			db		= config['name'],
		)
		registry = protocol.OpenIDRegistry()
		
		session_checker = session.SessionChecker(pool)
		session_realm = session.SessionRealm(pool, registry)
		
		openIDPortal = portal.Portal(session_realm)
		openIDPortal.registerChecker(session_checker)
		
		siteRoot = resource.ProviderPage(pool, openIDPortal)
		assetsRoot = static.File(resource.get_assets_path('webroot'))
		userRoot = resource.UserStubPage()
		
		loginPage = resource.LoginPage(pool, openIDPortal)
		logoutPage = resource.LogoutPage(pool, openIDPortal)
		infoPage = resource.InfoPage(pool, openIDPortal)
		identityPage = resource.IdentityPage(pool, openIDPortal)
		trustPage = resource.TrustPage(pool, openIDPortal)
		
		userRoot.putChild('login', loginPage)
		userRoot.putChild('logout', logoutPage)
		userRoot.putChild('info', infoPage)
		userRoot.putChild('identity', identityPage)
		userRoot.putChild('trust', trustPage)
		
		siteRoot.putChild('assets', assetsRoot)
		siteRoot.putChild('user', userRoot)
		
		if(config['hostname'] is None):
			import socket
			config['hostname'] = socket.gethostname()
		
		protocol.configure_urls(config['hostname'], config['server-port'])
		
		if(config['access-log'] != '-'):
			webFactory = appserver.NevowSite(siteRoot, logPath=config['access-log'])
		else:
			webFactory = appserver.NevowSite(siteRoot)
		webService = internet.TCPServer(int(config['server-port']), webFactory)
		
		return webService

serviceMaker = txOpenIDProvider()