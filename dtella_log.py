"""
Dtella - Logging Module
Copyright (C) 2008  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2008  Jacob Feisley (http://www.feisley.com/)
Copyright (C) 2008  Paul Marks (http://www.pmarks.net/)

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
import sys
import logging
import logging.handlers

from dtella_util import get_user_path, CHECK

# Defined Logging Levels
#
# CRITICAL  50
# ERROR     40
# WARNING   30
# INFO      20
# DEBUG     10
# PACKET    5
# NOTSET    0

LOG = None

def initLogger(filename, max_size, max_archives):
    global LOG
    CHECK(LOG is None)

    # Add custom levels
    logging.addLevelName(5, "PACKET")

    # Create LOG
    LOG = logging.getLogger()
    LOG.setLevel(5)

    # Create console handler and set level to error
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter("%(levelname).1s - %(message)s"))
    LOG.addHandler(ch)

    # Create file handler and set level to debug (rotates logs)
    fh = logging.handlers.RotatingFileHandler(
        get_user_path(filename), 'a', max_size, max_archives)
    fh.setLevel(5)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s - %(levelname).1s - %(message)s"))
    LOG.addHandler(fh)

