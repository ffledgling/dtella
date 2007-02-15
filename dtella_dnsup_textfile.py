"""
Dtella - DNS Updater Plugin (Text File)
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


from twisted.internet import defer

class TextFileUpdater(object):

    def __init__(self, fname):
        self.fname = fname


    def update(self, entries):

        keys = entries.keys()
        keys.sort()

        try:
            f = file(self.fname, 'w')

            for k in keys:
                f.write("%s=%s\n" % (k, entries[k]))

            f.close()

            return defer.succeed(None)

        except:
            return defer.fail()
