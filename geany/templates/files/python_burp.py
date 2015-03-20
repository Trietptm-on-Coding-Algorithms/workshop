#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
{fileheader}

from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender):
	def __init__(self, *args, **kwargs):
		super(BurpExtender, self).__init__(*args, **kwargs)

	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.callbacks.registerHttpListener(HttpListener())

class HttpListener(IHttpListener):
	def __init__(self, *args, **kwargs):
		super(HttpListener, self).__init__(*args, **kwargs)

	def processHttpMessage(self, tool_name, is_request, message_info):
		if not is_request:
			return
