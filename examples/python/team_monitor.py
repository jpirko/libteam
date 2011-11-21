#! /usr/bin/env python
"""
Team monitor

Copyright (c) 2011 Jiri Pirko <jpirko@redhat.com>

This library is free software; you can redistribute it and/or modify it
under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation version 2.1 of the License.
"""

__author__ = """
jpirko@redhat.com (Jiri Pirko)
"""

import sys
import team

def port_change_handler(t):
    print "------------------\nport change\n\tport list:"
    for port in t.port_list():
        print ("\tifname %s, linkup %d, changed %d, speed %d, duplex %d" %
                        (port.ifname, port.linkup, port.changed,
                         port.speed, port.duplex))

def option_change_handler(t):
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

    t.change_handler_register(port_change_handler, t,
                              team.TEAM_PORT_CHANGE)
    t.change_handler_register(option_change_handler, t,
                              team.TEAM_OPTION_CHANGE)
    t.loop_forever()

if __name__ == "__main__":
    main()
