"""
Dtella - Logging Module
Copyright (C) 2007  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2007  Jacob Feisley (http://www.feisley.com/)

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

import logging


class LogControl(object):

    def __init__(self, filename):
        self.logger = None
        
        #Add custom levels
        logging.addLevelName(5, "Packets")
        #create logger
        self.logger = logging.getLogger()
        self.logger.setLevel(5)
        #create console handler and set level to error
        self.ch = logging.StreamHandler()
        self.ch.setLevel(logging.DEBUG)
        #create file handler and set level to debug
        self.fh = logging.FileHandler(filename)
        self.fh.setLevel(5)
        
        #create formatter
        self.consoleFormat = logging.Formatter("%(levelname).1s - %(message)s")
        self.logfileFormat = logging.Formatter("%(asctime)s - %(levelname).1s - %(message)s")
        #add formatter to ch and fh
        self.ch.setFormatter(self.consoleFormat)
        self.fh.setFormatter(self.logfileFormat)
        #add ch and fh to logger
        self.logger.addHandler(self.ch)
        self.logger.addHandler(self.fh)

#Defined Logging Levels
#
# CRITICAL  	50
# ERROR         40
# WARNING 	30
# INFO 	        20
# DEBUG         10
# PACKETS       5
# NOTSET 	0
#







