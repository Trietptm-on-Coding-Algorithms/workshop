#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  github.py
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

"""
pip install pygit2 PyGithub
"""

import os
import re
import subprocess

import gtk
import geany

import github
import pygit2
import workshop
import workshop.configuration

REGEX_GITHUB = re.compile('^(git@|https://)github.com[:/]([\w-]+/[\w\-\.]+).git$', flags=re.IGNORECASE)

def git_fetch(repo, remote_name=None):
	if not workshop.which('git'):
		return
	remote_name = (remote_name or '--all')
	args = ['git', 'fetch', remote_name]
	proc_h = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=repo)
	return proc_h.wait()

class GeanyPlugin(geany.Plugin):
	__plugin_name__ = 'GitHub'
	__plugin_version__ = '1.0'
	__plugin_description__ = 'GitHub API Integration'
	__plugin_author__ = 'Spencer McIntyre <zeroSteiner@gmail.com>'

	def __init__(self):
		self.config = workshop.configuration.Configuration(os.environ['$WORKSHOP_CONFIG'], 'geanypy_plugins.github_api')
		self.project_menu_github = None
		geany.signals.connect('project_open', self.init_project)
		geany.signals.connect('project_close', self.cleanup_project)
		if geany.app.project:
			self.init_project(geany.signals, geany.app.project)

	def init_project(self, signal_manager, project):
		if self.project_uses_github:
			github = self.github

			submenu_github = gtk.Menu()
			menu_item = gtk.MenuItem('GitHub')
			menu_item.set_submenu(submenu_github)
			geany.main_widgets.project_menu.append(menu_item)
			self.project_menu_github = menu_item
			self.project_menu_github_menu = submenu_github

			for remote_name in self.config.get('remote_names'):
				gh_slug = self.project_github_get_slug(remote_name)
				if not gh_slug:
					continue
				gh_submenu = gtk.Menu()
				menu_item = gtk.MenuItem(gh_slug.split('/')[0])
				menu_item.set_submenu(gh_submenu)
				self.project_menu_github_menu.append(menu_item)
				remote = self.project_git_get_remote(remote_name)
				pr_refspec = '+refs/pull/*/head:refs/remotes/' + remote_name + '/pr/*'
				if not pr_refspec in remote.fetch_refspecs:
					remote.add_fetch(pr_refspec)
					remote.save()
					geany.msgwindow.status_add('GitHub pull request refspec added for ' + gh_slug)

				menu_item = gtk.MenuItem('Home')
				gh_submenu.append(menu_item)
				menu_item.connect('activate', self.show_uri, 'https://github.com/' + gh_slug)

				gh_repo = github.get_repo(gh_slug)
				if gh_repo.has_wiki:
					menu_item = gtk.MenuItem('Wiki')
					gh_submenu.append(menu_item)
					menu_item.connect('activate', self.show_uri, 'https://github.com/' + gh_slug + '/wiki')

				menu_item = gtk.MenuItem('File')
				gh_submenu.append(menu_item)
				menu_item.connect('activate', lambda _, gh_slug: self.project_github_open_file(gh_slug=gh_slug), gh_slug)

				gh_pr_submenu = gtk.Menu()
				prs = 0
				for pr in gh_repo.get_pulls():
					prs += 1
					pr_title = "#{0} - {1}".format(pr.number, pr.title)
					if len(pr_title) > 50:
						pr_title = pr_title[:47] + '...'
					menu_item = gtk.MenuItem(pr_title)
					gh_pr_submenu.append(menu_item)
					menu_item.connect('activate', lambda _, prn, remote_name: self.project_github_open_pr(prn, remote_name), pr.number, remote_name)
					if prs == self.config.get('max_prs'):
						break
				if prs:
					menu_item = gtk.MenuItem('Pull Requests')
					menu_item.set_submenu(gh_pr_submenu)
					gh_submenu.append(menu_item)

			self.project_menu_github.show_all()
			geany.msgwindow.status_add('GitHub menu added for current project')

	@property
	def github(self):
		return github.Github()

	def show_uri(self, *args):
		uri = args[-1]
		gtk.show_uri(None, uri, gtk.gdk.CURRENT_TIME)

	def cleanup(self):
		self.menu_item.destroy()

	def cleanup_project(self, signal_manager):
		if not self.project_menu_github:
			return
		geany.main_widgets.project_menu.remove(self.project_menu_github)
		for child in self.project_menu_github.get_children():
			child.destroy()
		self.project_menu_github = None

	@property
	def project_uses_git(self):
		return isinstance(self.project_git_repo, pygit2.Repository)

	@property
	def project_uses_github(self):
		return isinstance(self.project_github_get_url(), (str, unicode))

	@property
	def project_git_repo(self):
		if not geany.app.project:
			return None
		project_base = geany.app.project.base_path
		if not os.path.isdir(os.path.join(project_base, '.git')):
			return None
		try:
			repo = pygit2.Repository(project_base)
		except KeyError:
			return None
		return repo

	def project_git_get_remote(self, name):
		matching = filter(lambda r: r.name == name, self.project_git_repo.remotes)
		if not len(matching):
			return None
		return matching[0]

	def project_github_get_slug(self, name=None):
		url = self.project_github_get_url(name)
		if url:
			return REGEX_GITHUB.match(url).group(2)

	def project_github_get_url(self, name=None):
		if not self.project_uses_git:
			return None
		if name:
			remote_names = [name]
		else:
			remote_names = self.config.get('remote_names')
		for remote_name in remote_names:
			remote = self.project_git_get_remote(remote_name)
			if not remote:
				continue
			match = REGEX_GITHUB.match(remote.url)
			if not match:
				continue
			return remote.url

	def project_github_open_pr(self, pr_number, remote_name):
		gh_slug = self.project_github_get_slug(remote_name)
		gh_pull = self.github.get_repo(gh_slug).get_pull(pr_number)

		git_repo = self.project_git_repo
		git_ref_str = "refs/remotes/{0}/pr/{1}".format(remote_name, pr_number)
		try:
			git_ref = git_repo.lookup_reference(git_ref_str)
		except KeyError:
			git_ref = None
		if not git_ref or str(git_ref.target) != gh_pull.head.sha:
			git_fetch(geany.app.project.base_path, remote_name)
			git_ref = git_repo.lookup_reference(git_ref_str)
			if str(git_ref.target) != gh_pull.head.sha:
				geany.dialogs.show_msgbox("Local Git Repo Does Not Have Correct Reference")
				return
		map(lambda doc: doc.close(), geany.document.get_documents_list())
		gh_files = filter(lambda f: f.status != 'removed', gh_pull.get_files())
		if len(gh_files) > 10:
			if not geany.dialogs.show_question("{0} Files Have Been Modified Or Deleted. Open Them All?".format(len(gh_files))):
				return
		git_repo.checkout(git_ref)
		for gh_file in gh_files:
			file_name = os.path.join(geany.app.project.base_path, gh_file.filename)
			geany.document.open_file(file_name)
		geany.msgwindow.status_add("GitHub Pull Request {0} #{1} opened".format(gh_slug, pr_number))

	def project_github_open_file(self, file_name=None, gh_slug=None):
		gh_slug = gh_slug or self.project_github_get_slug()
		current_doc = geany.document.get_current()
		relative_path = None
		if isinstance(file_name, (str, unicode)):
			relative_path = os.path.relpath(file_name, geany.app.project.base_path)
		elif current_doc:
			if current_doc.file_name.startswith(geany.app.project.base_path):
				relative_path = os.path.relpath(current_doc.file_name, geany.app.project.base_path)
			else:
				geany.dialogs.show_msgbox("The Current Document Is Not Part Of The Project")
				return
		else:
			geany.dialogs.show_msgbox("No Document Is Open")
			return
		menu_item = gtk.MenuItem('File')
		self.project_menu_github_menu.append(menu_item)
		url = "https://github.com/{0}/blob/master/{1}".format(gh_slug, relative_path)
		self.show_uri(url)
