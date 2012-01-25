#! /usr/bin/env python
"""
Team monitor

   Copyright (C) 2011 Jiri Pirko <jpirko@redhat.com>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
"""

__author__ = """
jpirko@redhat.com (Jiri Pirko)
"""

import sys
import team

def port_change_handler_func(t):
    print "------------------\nport change\n\tport list:"
    for port in t.port_list():
        print ("\tifname %s, linkup %d, changed %d, speed %d, duplex %d, removed %d" %
                        (port.ifname, port.linkup, port.changed,
                         port.speed, port.duplex, port.removed))

def option_change_handler_func(t):
    print "------------------\noption change\n\toption list:"
    for option in t.option_list():
        print ("\t%s = %s (changed %d)" % (option.name, option.value,
                                           option.changed))

def main():
    appname = sys.argv[0]
    args = sys.argv[1:]

    if len(args) < 1:
        print "Usage: %s TEAMDEV" % appname
        sys.exit()

    ifname = args[0]

    t = team.Team(ifname)

    port_change_handler = team.TeamChangeHandler(
                                    port_change_handler_func, t,
                                    team.TEAM_PORT_CHANGE)
    t.change_handler_register(port_change_handler)
    option_change_handler = team.TeamChangeHandler(
                                    option_change_handler_func, t,
                                    team.TEAM_OPTION_CHANGE)
    t.change_handler_register(option_change_handler)

    t.loop_forever()

if __name__ == "__main__":
    main()
