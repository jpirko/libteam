#! /usr/bin/env python
"""
Team daemon example. Implements very basic active backup functionality.
Note that this application spawns its own team device instead of connecting
to an existing one.

Copyright (c) 2011 Jiri Pirko <jpirko@redhat.com>

This library is free software; you can redistribute it and/or modify it
under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation version 2.1 of the License.
"""

__author__ = """
jpirko@redhat.com (Jiri Pirko)
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
    print "  -a, --active-port=NETDEV           initial active port"
    sys.exit()


def port_change_handler_func(t):
    print "------------------\nport change\n\tport list:"
    for port in t.port_list():
        print ("\tifname %s, linkup %d, changed %d, speed %d, duplex %d" %
                        (port.ifname, port.linkup, port.changed,
                         port.speed, port.duplex))

def option_change_handler_func(t):
    print "------------------\noption change\n\toption list:"
    for option in t.option_list():
        print ("\t%s = %s (changed %d)" % (option.name, option.value,
                                           option.changed))

orig_active_hwaddr = None

def change_active_port(t, old_active, new_active):
    global orig_active_hwaddr
    if old_active:
        old_active.set_hwaddr(orig_active_hwaddr)

    t.set_active_port(new_active)
    mac = t.get_hwaddr()
    orig_active_hwaddr = new_active.get_hwaddr()
    new_active.set_hwaddr(mac)
    print "*** new active port \"%s\" selected" % new_active

def port_change_handler_ab_func(t):
    active = t.get_active_port()
    print "*** current active port is \"%s\"" % active
    if active.linkup:
        return
    elif active.changed:
        print "*** active port \"%s\" lost link" % active

    best = None
    for port in t.port_list():
        if port.linkup:
            if (not best or
                port.speed > best.speed or
                (port.speed == best.speed and port.duplex > port.duplex)):
                best = port
    if best:
        change_active_port(t, active, best)

def main():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "ht:p:m:a:",
            ["help", "team-name=", "port=", "mode=", "active-port="]
        )
    except getopt.GetoptError, err:
        print str(err)
        usage()

    team_name = None
    mode_name = None
    active_port_name = None
    ports = []
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
        elif opt in ("-t", "--team-name"):
            team_name = arg
        elif opt in ("-p", "--port"):
            ports.append(arg)
        elif opt in ("-m", "--mode"):
            mode_name = arg
        elif opt in ("-a", "--active-port"):
            active_port_name = arg

    appname = sys.argv[0]
    args = sys.argv[1:]

    if not team_name:
        def_team_name = "teamtest0"
        print "Using default team name \"%s\"" % def_team_name
        team_name = def_team_name
    if not mode_name:
        def_mode_name = "roundrobin"
        print "Using default mode \"%s\"" % def_mode_name
        mode_name = def_mode_name

    print "team name is \"%s\"" % team_name
    t = team.Team(team_name, create=True, destroy=True)
    t.set_mode_name(mode_name)
    for port in ports:
        t.port_add(port)

    t.check_events()

    port_change_handler = team.TeamChangeHandler(
                                    port_change_handler_func, t,
                                    team.TEAM_PORT_CHANGE)
    t.change_handler_register(port_change_handler)

    option_change_handler = team.TeamChangeHandler(
                                    option_change_handler_func, t,
                                    team.TEAM_OPTION_CHANGE)
    t.change_handler_register(option_change_handler)

    if mode_name == "activebackup":
        if not active_port_name:
            if not ports:
                usage()
            active_port_name = ports[0]
        port = t.get_port(active_port_name)
        change_active_port(t, None, port)
        port_change_handler_ab = team.TeamChangeHandler(
                                    port_change_handler_ab_func, t,
                                    team.TEAM_PORT_CHANGE)
        t.change_handler_register(port_change_handler_ab)

    def kill_loop(signum, frame):
        t.kill_loop()

    signal.signal(signal.SIGINT, kill_loop)
    signal.signal(signal.SIGHUP, kill_loop)
    signal.signal(signal.SIGTERM, kill_loop)

    t.loop_forever()
    t.close()

if __name__ == "__main__":
    main()
