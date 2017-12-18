#! /usr/bin/env python
"""
Team daemon example. Implements very basic active backup functionality.
Note that this application spawns its own team device instead of connecting
to an existing one.

   Copyright (C) 2011-2015 Jiri Pirko <jiri@resnulli.us>

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
jiri@resnulli.us (Jiri Pirko)
"""

import sys
import getopt
import team
import signal

def usage():
    """
    Print usage of this app
    """
    print "Usage: team_daemon.py [OPTION...]"
    print ""
    print "  -h, --help                         print this message"
    print "  -t, --team-name=NAME               name of team device"
    print "  -p, --port=NETDEV                  port device (can be defined multiple times)"
    print "  -m, --mode=MODENAME                name of team mode"
    sys.exit()

class TeamDaemon(object):
    def __init__(self):
        def_team_name = "teamtest0"
        self._team_name = def_team_name
        def_mode_name = "roundrobin"
        self._mode_name = def_mode_name
        self._port_names = []
        self._old_active_hwaddr = None

        self._parse_cmdline()

        if self._team_name == def_team_name:
            print "Using default team name \"%s\"" % def_team_name

        if self._mode_name == def_mode_name:
            print "Using default mode \"%s\"" % def_mode_name

        print "Team name is \"%s\"" % self._team_name
        self._t = team.Team(self._team_name, create=True, destroy=True)

        self._t.set_mode_name(self._mode_name)
        for port_name in self._port_names:
            self._t.port_add(port_name)

        if self._mode_name == "activebackup":
            self._port_change_handler_ab = team.TeamChangeHandler(
                                    self._port_change_handler_ab_func, None,
                                    team.TEAM_PORT_CHANGE)
            self._t.change_handler_register(self._port_change_handler_ab)

        self._port_change_handler = team.TeamChangeHandler(
                                    self._port_change_handler_func, None,
                                    team.TEAM_PORT_CHANGE)
        self._t.change_handler_register(self._port_change_handler)

        self._option_change_handler = team.TeamChangeHandler(
                                    self._option_change_handler_func, None,
                                    team.TEAM_OPTION_CHANGE)
        self._t.change_handler_register(self._option_change_handler)

    def _parse_cmdline(self):
        try:
            opts, args = getopt.getopt(
                sys.argv[1:],
                "ht:p:m:",
                ["help", "team-name=", "port=", "mode="]
            )
        except getopt.GetoptError, err:
            print str(err)
            usage()

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
            elif opt in ("-t", "--team-name"):
                self._team_name = arg
            elif opt in ("-p", "--port"):
                self._port_names.append(arg)
            elif opt in ("-m", "--mode"):
                self._mode_name = arg

    def _port_change_handler_func(self, unused):
        print "------------------\nport change\n\tport list:"
        for port in self._t.port_list():
            print ("\tifname %s, linkup %d, changed %d, speed %d, duplex %d, removed %d" %
                        (port.ifname, port.linkup, port.changed,
                         port.speed, port.duplex, port.removed))
        return 0

    def _option_change_handler_func(self, unused):
        print "------------------\noption change\n\toption list:"
        for option in self._t.option_list():
            print ("\t%s = %s (changed %d)" % (option.name, option.value,
                                               option.changed))
        return 0

    def _change_active_port(self, old_active, new_active):
        if old_active:
            old_active.set_hwaddr(self._old_active_hwaddr)

        self._t.set_active_port(new_active)
        mac = self._t.get_hwaddr()
        self._old_active_hwaddr = new_active.get_hwaddr()
        new_active.set_hwaddr(mac)
        print "*** new active port \"%s\" selected" % new_active

    def _port_change_handler_ab_func(self, unused):
        try:
            active = self._t.get_active_port()
            if active:
                print "*** current active port is \"%s\"" % active
                if active.linkup:
                    return
                elif active.changed:
                    print "*** active port \"%s\" lost link" % active
        except KeyError:
            active = None
            print "*** no current active port set"

        best = None
        for port in self._t.port_list():
            if port.linkup:
                if (not best or
                    port.speed > best.speed or
                    (port.speed == best.speed and port.duplex > best.duplex)):
                    best = port
        if best:
            self._change_active_port(active, best)

    def close(self):
        self._t.close()

    def loop_forever(self):
        self._t.loop_forever()

    def kill_loop(self):
        self._t.kill_loop()

def main():
    team_daemon = TeamDaemon()

    def kill_loop(signum, frame):
        team_daemon.kill_loop()

    signal.signal(signal.SIGINT, kill_loop)
    signal.signal(signal.SIGHUP, kill_loop)
    signal.signal(signal.SIGTERM, kill_loop)

    team_daemon.loop_forever()
    team_daemon.close()

if __name__ == "__main__":
    main()
