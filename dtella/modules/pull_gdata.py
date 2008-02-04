"""
Dtella - Google Spreadsheets Puller Module
Copyright (C) 2008  Dtella Labs (http://dtella.org)
Copyright (C) 2008  Paul Marks (http://pmarks.net)

$Id$

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

from twisted.internet import reactor
from twisted.internet.threads import deferToThread
import urllib
import xml.dom.minidom

PAGE_TEMPLATE = ("https://spreadsheets.google.com/feeds/cells/"
                 "%s/1/public/basic?max-col=1&max-row=10")

class GDataPuller(object):

    def __init__(self, sheet_key):
        self.sheet_key = sheet_key

    def startText(self):
        return "Requesting config data from Google Spreadsheet..."

    def query(self):

        def f(url):
            return urllib.urlopen(url).read()

        d = deferToThread(f, PAGE_TEMPLATE % self.sheet_key)

        def cb(result):
            config_list = []
            doc = xml.dom.minidom.parseString(result)
            for c in doc.getElementsByTagName("content"):
                if c.firstChild:
                    config_list.append(str(c.firstChild.nodeValue))
            return config_list

        d.addCallback(cb)
        return d

