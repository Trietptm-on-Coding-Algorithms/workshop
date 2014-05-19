#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  webtools.py
#
#  Copyright 2014 Spencer McIntyre <zeroSteiner@gmail.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#

import gtk
import geany


class GeanyPlugin(geany.Plugin):
	__plugin_name__ = 'Web Tools'
	__plugin_version__ = '1.0'
	__plugin_description__ = 'Web Tool Shortcuts'
	__plugin_author__ = 'Spencer McIntyre <zeroSteiner@gmail.com>'

	def __init__(self):
		menu_item = gtk.MenuItem('Regex Debugger')
		menu_item.show()
		geany.main_widgets.tools_menu.append(menu_item)
		menu_item.connect('activate', self.show_uri, 'https://www.debuggex.com/')
		self.tools_menu_regex_debugger = menu_item

	def show_uri(self, *args):
		uri = args[-1]
		gtk.show_uri(None, uri, gtk.gdk.CURRENT_TIME)