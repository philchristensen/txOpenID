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
						["server-port", "P", 8887, "Port to use for web server."],
					]

class txOpenIDConsumer(object):
	implements(service.IServiceMaker, IPlugin)
	tapname = "txopenid-consumer"
	description = "Run an example OpenID consumer site."
	options = Options
	
	def makeService(self, config):
		pool = db.Connection(**config)
		session_checker = session.SessionChecker(pool)
		session_realm = session.SessionRealm(pool, None)
		
		openIDPortal = portal.Portal(session_realm)
		openIDPortal.registerChecker(session_checker)
		
		siteRoot = resource.ConsumerPage(pool, openIDPortal)
		assetsRoot = static.File(resource.get_assets_path('webroot'))
		
		siteRoot.putChild('assets', assetsRoot)
		
		webFactory = appserver.NevowSite(siteRoot)
		webService = internet.TCPServer(int(config['server-port']), webFactory)
		
		return webService

serviceMaker = txOpenIDConsumer()