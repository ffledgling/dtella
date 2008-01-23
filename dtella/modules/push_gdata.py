"""
Dtella - Config Updater Plugin (Google Spreadsheets)
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

from twisted.internet import threads
import atom.service
import gdata.spreadsheet
import gdata.spreadsheet.service


def ForceSSL():
    # Patch the Atom library to force all GData requests to run over SSL.

    real_BuildUri = atom.service.BuildUri
    def BuildUri(*args, **kw):
        uri = real_BuildUri(*args, **kw)
        if uri.startswith("http:"):
            uri = "https:" + uri[5:]
        return uri
    atom.service.BuildUri = BuildUri

ForceSSL()


class GDataUpdater(object):

    def __init__(self, email, password, sheet_key):
        self.email = email
        self.password = password
        self.sheet_key = sheet_key


    def update(self, entries):
        d = threads.deferToThread(self._submitData, entries)
        return d


    def _submitData(self, entries):
        keys = entries.keys()
        keys.sort()

        # Log in to Google Spreadsheets
        gd_client = gdata.spreadsheet.service.SpreadsheetsService()
        gd_client.email = self.email
        gd_client.password = self.password
        gd_client.source = "Dtella_GData_Updater_0"
        gd_client.ProgrammaticLogin()

        # Work within the upper-left 1x10 block of cells.
        query = gdata.spreadsheet.service.CellQuery()
        query.max_col = '1'
        query.max_row = '10'
        query.return_empty = 'true'

        # Get existing cells
        feed = gd_client.GetCellsFeed(self.sheet_key, '1', query=query)

        # Prepare batch object for updates.
        batch_feed = gdata.spreadsheet.SpreadsheetsCellsFeed()

        n_changes = 0

        # Walk through the existing cells
        for entry in feed.entry:

            # Decide what the new cell value should be
            try:
                k = keys[int(entry.cell.row) - 1]
                new_value = "%s=%s" % (k, entries[k])
            except IndexError:
                new_value = ""

            old_value = entry.cell.inputValue or ""

            # Update cells which have changed
            if old_value != new_value:
                entry.cell.inputValue = new_value
                batch_feed.AddUpdate(entry)
                n_changes += 1

        # Push the updates
        if batch_feed.entry:
            gd_client.ExecuteBatch(batch_feed, url=feed.GetBatchLink().href)

        return ("Cells modified = %d" % n_changes)
