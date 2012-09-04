#! /usr/bin/env python
"""
Basic test.

   Copyright (C) 2012 Jiri Pirko <jpirko@redhat.com>

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
import os
import getopt
import subprocess

def usage():
    """
    Print usage of this app
    """
    print "Usage: team_basic_test.py [OPTION...]"
    print ""
    print "  -h, --help                         print this message"
    print "  -c, --loop-count=NUMBER            number of loops (default 1)"
    print "  -p, --port=NETDEV                  port device (can be defined multiple times)"
    sys.exit()

class CmdExecFailedException(Exception):
    def __init__(self, retval):
        self.__retval = retval

    def __str__(self):
        return "Command execution failed: %s" % self.__retval

class CmdExecUnexpectedOutputException(Exception):
    def __init__(self, output, expected_output):
        self.__output = output
        self.__expected_output = expected_output

    def __str__(self):
        return "Command execution output unexpected: \"%s\" != \"%s\"" % (self.__output, self.__expected_output)

def print_output(out_type, string):
    print("%s:\n"
          "----------------------------\n"
          "%s"
          "----------------------------" % (out_type, string))

def cmd_exec(cmd, expected_output=None, cleaner=False):
    cmd = cmd.rstrip(" ")
    if not cleaner:
        print("# \"%s\"" % cmd)
    subp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (data_stdout, data_stderr) = subp.communicate()

    if subp.returncode and not cleaner:
        if data_stdout:
            print_output("Stdout", data_stdout)
        if data_stderr:
            print_output("Stderr", data_stderr)
        raise CmdExecFailedException(subp.returncode)
    output = data_stdout.rstrip()
    if expected_output:
        if output != expected_output:
            raise CmdExecUnexpectedOutputException(output, expected_output)
    return output

class TeamBasicTest:
    def __init__(self):
        self._team_dev_name = "testteamx"
        self._team_modes = ["broadcast", "roundrobin", "activebackup", "loadbalance"]
        self._loop_count = 1
        self._port_names = []

    def set_loop_count(self, new_loop_count):
        self._loop_count = new_loop_count

    def port_add(self, port_name):
        self._port_names.append(port_name)

    def _run_one_mode(self, mode_name):
        team_name = self._team_dev_name
        cmd_exec("ip link add %s type team" % team_name)
        try:
            self._created_teams.append(team_name)
            cmd_exec("teamnl %s getoption mode" % team_name, "*NOMODE*")
            cmd_exec("teamnl %s setoption mode %s" % (team_name, mode_name))
            cmd_exec("teamnl %s getoption mode" % team_name, mode_name)

            for port_name in self._port_names:
                cmd_exec("ip link set %s down" % port_name)
                cmd_exec("ip link set %s master %s" % (port_name, team_name))

            cmd_exec("ip link set %s up" % team_name)
            cmd_exec("ip addr add 192.168.241.231/24 dev %s" % team_name)
            cmd_exec("ip link set %s down" % team_name)
            cmd_exec("ip addr flush dev %s" % team_name)

            cmd_exec("teamnl %s options" % team_name)
            cmd_exec("teamnl %s ports" % team_name)

            for port_name in self._port_names:
                cmd_exec("ip link set %s nomaster" % port_name)
        finally:
                cmd_exec("ip link del %s" % team_name)

    def _create_team_initscript(self):
        f = open("/etc/sysconfig/network-scripts/ifcfg-%s" % self._team_dev_name, "w")
        f.write(
"""
DEVICE="%s"
DEVICETYPE="Team"
ONBOOT="no"
BOOTPROTO=none
NETMASK=255.255.255.0
IPADDR=192.168.241.231
TEAM_CONFIG='{"runner": {"name": "activebackup"}}'
""" % self._team_dev_name)
        f.close()
        cmd_exec("ifup %s" % self._team_dev_name)
    
    def _create_port_initscript(self, port_name):
        f = open("/etc/sysconfig/network-scripts/ifcfg-%s" % port_name, "w")
        f.write(
"""
DEVICE="%s"
DEVICETYPE="TeamPort"
ONBOOT="yes"
TEAM_MASTER="%s"
TEAM_PORT_CONFIG='{"prio": 10}'
""" % (port_name, self._team_dev_name))
        f.close()
        cmd_exec("ifup %s" % port_name)

    def _run_teamd_initscripts(self):
        os.makedirs("/tmp/team_test/")
        try:
            ifcfg_files = " ".join(["ifcfg-%s" % port_name for port_name in self._port_names])
            cmd_exec("tar --ignore-failed-read -C /etc/sysconfig/network-scripts/ -cf /tmp/team_test/initscripts_bkp.tar %s" % ifcfg_files)
            self._create_team_initscript()
            for port_name in self._port_names:
                self._create_port_initscript(port_name)
            cmd_exec("ifdown %s" % self._team_dev_name)
        except:
            cmd_exec("ifdown %s" % self._team_dev_name, cleaner=True)
            cmd_exec("ip link del %s" % self._team_dev_name, cleaner=True)
            raise
        finally:
            cmd_exec("tar -C /etc/sysconfig/network-scripts/ -xf /tmp/team_test/initscripts_bkp.tar")
            os.unlink("/tmp/team_test/initscripts_bkp.tar")
            os.removedirs("/tmp/team_test/")

    def _run_one_loop(self, run_nr):
        print "RUN #%d" % (run_nr)
        self._created_teams = []
        try:
            for mode_name in self._team_modes:
                self._run_one_mode(mode_name)
            self._run_teamd_initscripts()
        finally:
            cmd_exec("modprobe -r team_mode_loadbalance team_mode_roundrobin team_mode_activebackup team_mode_broadcast team");

    def run(self):
        for i in xrange(self._loop_count):
            self._run_one_loop(i + 1)

def main():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hc:p:",
            ["help", "loop-count=", "port="]
        )
    except getopt.GetoptError, err:
        print str(err)
        usage()

    btest = TeamBasicTest()

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
        elif opt in ("-c", "--loop-count"):
            btest.set_loop_count(int(arg))
        elif opt in ("-p", "--port"):
            btest.port_add(arg)

    btest.run()

if __name__ == "__main__":
    main()
