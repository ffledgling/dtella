"""
Dtella - DNS Updater Plugin (for yi.org)
Copyright (C) 2007  Dtella Labs (http://www.dtella.org)
Copyright (C) 2007  Paul Marks

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

import twisted.web.client
import twisted.web.error
from twisted.internet import reactor
from urllib import quote_plus

import re

# This regex should exactly match the formatting of the table on yi.org
record_re = re.compile(
    r"""
        ^\s*<TR>
        <TD[^>]+><A[^>]+>(?P<id>[^<]+)</A>
        <TD><A[^>]+>(?P<name>[^<]+)</A></TD>
        <TD>(?P<type>[^<]+)</TD>
        <TD>(?P<data>[^<]+)</TD>
        <TD>(?P<enabled>[^<]+)</TD>
        <TD>(?P<hits>[^<]+)</TD>
        <TD>(?P<date>[^<]+)</TD>
        </TR>\s*$
    """,
    re.MULTILINE | re.VERBOSE)


class UpdateError(Exception):
    pass


# TODO: integrate with the rest of the logging
def log(text):
    print "YiUpdater: %s" % text


class YiUpdater(object):

    def __init__(self, username, password, host_id, ttl=300):
        self.username = username
        self.password = password
        self.host_id = str(host_id)
        self.ttl = str(ttl)


    def update(self, entries):
        log("Logging in")

        def fudge(value):
            return ''.join(["%%%02X" % ord(c) for c in value])

        postdata = "login=%s&passwd=%s" % (
            fudge(self.username), fudge(self.password))

        factory = twisted.web.client.HTTPClientFactory(
            "http://www.yi.org/login",
            followRedirect=False,
            method="POST",
            postdata=postdata)

        reactor.connectTCP("www.yi.org", 80, factory)

        d = factory.deferred

        def noRedirectHandler(result):
            raise UpdateError("Unexpected login response")

        def redirectHandler(failure):
            failure.trap(twisted.web.error.PageRedirect)

            if failure.value.location == '/admin':
                log("Logged in")
                cookies = {'session': factory.cookies['session']}
                return self._getRecords(entries, cookies)
            else:
                raise UpdateError("Unexpected login response")

        d.addCallbacks(noRedirectHandler, redirectHandler)
        return d


    def _getRecords(self, entries, cookies):

        d = twisted.web.client.getPage(
            "http://www.yi.org/admin/host.pl?id=%s" % self.host_id,
            followRedirect=False,
            cookies=cookies)

        def cb(result):
            if ("(#%s)" % self.host_id) not in result:
                raise UpdateError("Unexpected response.  Bad host ID?")

            log("Got record table")

            keys = entries.keys()
            keys.sort()
            key_i = 0

            tasks = []
            records = []

            for m in record_re.finditer(result):
                record = m.groupdict()
                if record['enabled'] == 'Y' and record['type'] == 'TXT':
                    records.append(record)

            records.sort(key=lambda r: int(r['id']))

            for record in records:
                if key_i < len(keys):
                    # Change existing record
                    data = "%s=%s" % (keys[key_i], entries[keys[key_i]])
                    tasks.append( (record['id'], data) )
                    key_i += 1

                else:
                    # Delete unnecessary record
                    tasks.append( (record['id'], '_DEL_') )

            while key_i < len(keys):
                # Add new record
                data = "%s=%s" % (keys[key_i], entries[keys[key_i]])
                tasks.append( ('_NEW_', data) )
                key_i += 1

            return self._submitData(tasks, cookies)

        d.addCallback(cb)
        return d


    def _submitData(self, tasks, cookies):

        log("Running Tasks")
        
        def cb(result):
            if not tasks:
                return self._doLogout(cookies)
            
            rec_id, data = tasks.pop(0)

            if rec_id == '_NEW_':
                # New
                postdata = {
                    'id': 'new',
                    'namespace': self.host_id,
                    'type': 'TXT',
                    'data': quote_plus(data),
                    'ttl': self.ttl,
                    'aux': '0',
                    'wc': '0'
                    }

            elif data == '_DEL_':
                # Delete
                postdata = {
                    'id': rec_id,
                    'data': 'bye',
                    'aux': '0',
                    'ttl': self.ttl,
                    'delete': 'Delete',
                    'confirm_delete': 1
                    }
            else:
                # Change
                postdata = {
                    'id': rec_id,
                    'data': quote_plus(data),
                    'ttl': self.ttl,
                    'aux': '0',
                    'save': 'Save'
                    }

            postdata = '&'.join([
                "%s=%s" % (k,v) for (k,v) in postdata.iteritems()])

            log("Setting %s->%s" % (rec_id, data))

            d = twisted.web.client.getPage(
                "http://www.yi.org/admin/rr.pl",
                method="POST",
                followRedirect=False,
                postdata=postdata,
                cookies=cookies)

            d.addCallback(cb)
            return d

        return cb(None)


    def _doLogout(self, cookies):
        log("Logging out")
        
        d = twisted.web.client.getPage(
            "http://www.yi.org/login?logout=1",
            followRedirect=False,
            cookies=cookies)

        def noRedirectHandler(result):
            raise UpdateError("Unexpected logout response")

        def redirectHandler(failure):
            failure.trap(twisted.web.error.PageRedirect)

            if failure.value.location == "/logout.shtml":
                log("Logged out")
            else:
                raise UpdateError("Unexpected logout response")

        d.addCallbacks(noRedirectHandler, redirectHandler)
        return d

