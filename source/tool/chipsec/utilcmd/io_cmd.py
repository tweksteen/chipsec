#!/usr/local/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#



"""
The io command allows direct access to read and write I/O port space.
"""

__version__ = '1.0'

from chipsec.command import BaseCommand

# Port I/O
class PortIOCommand(BaseCommand):
    """
    >>> chipsec_util io <io_port> <width> [value]

    Examples:

    >>> chipsec_util io 0x61 1
    >>> chipsec_util io 0x430 byte 0x0
    """
    def requires_driver(self):
        if len(self.argv) < 3:
            return False
        return True

    def run(self):
        if 3 > len(self.argv):
            print PortIOCommand.__doc__
            return

        try:
            io_port = int(self.argv[2],16)

            if 3 == len(self.argv):
                width = 1
            else:
                if 'byte' == self.argv[3]:
                    width = 1
                elif 'word' == self.argv[3]:
                    width = 2
                elif 'dword' == self.argv[3]:
                    width = 4
                else:
                    width = int(self.argv[3])
        except:
            print PortIOCommand.__doc__
            return

        if 5 == len(self.argv):
            value = int(self.argv[4], 16)
            self.logger.log( "[CHIPSEC] OUT 0x%04X <- 0x%08X (size = 0x%02x)" % (io_port, value, width) )
            if 1 == width:
                self.cs.io.write_port_byte( io_port, value )
            elif 2 == width:
                self.cs.io.write_port_word( io_port, value )
            elif 4 == width:
                self.cs.io.write_port_dword( io_port, value )
            else:
                print "ERROR: Unsupported width 0x%x" % width
                return
        else:
            if 1 == width:
                value = self.cs.io.read_port_byte( io_port )
            elif 2 == width:
                value = self.cs.io.read_port_word( io_port )
            elif 4 == width:
                value = self.cs.io.read_port_dword( io_port )
            else:
                print "ERROR: Unsupported width 0x%x" % width
                return
            self.logger.log( "[CHIPSEC] IN 0x%04X -> 0x%08X (size = 0x%02x)" % (io_port, value, width) )

commands = { 'io': PortIOCommand }
