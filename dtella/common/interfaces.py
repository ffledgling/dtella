"""
Dtella - Common Interfaces
Copyright (C) 2008  Dtella Labs (http://www.dtella.org)
Copyright (C) 2008  Paul Marks

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

from zope.interface import Interface

class IDtellaStateObserver(Interface):
    def event_AddNick(n):
        pass
    def event_RemoveNick(n, reason):
        pass
    def event_UpdateInfo(n):
        pass
    def event_ChatMessage(n, nick, text, flags):
        pass
    def event_DtellaUp():
        pass
    def event_DtellaDown():
        pass
    def event_KickMe(lines, rejoin_time):
        pass

class IDtellaNickNode(Interface):
    def setInfo(info):
        pass
    def setNoUser():
        pass
    def event_PrivateMessage(main, text, fail_cb):
        pass
    def event_ConnectToMe(main, port, use_ssl, fail_cb):
        pass
    def event_RevConnectToMe(main, fail_cb):
        pass
    def checkRevConnectWindow():
        pass

