"""
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

import capi
import select
import struct

TEAM_ANY_CHANGE = capi.TEAM_ANY_CHANGE
TEAM_PORT_CHANGE = capi.TEAM_PORT_CHANGE
TEAM_OPTION_CHANGE = capi.TEAM_OPTION_CHANGE

class TeamError(Exception):
    pass

class TeamLibError(TeamError):
    def __init__(self, msg, err = 0):
        self._msg = msg
        self._err = err

    def __str__(self):
        msg = self._msg
        if self._err:
            msg += " Err=%d" % self._err
        return msg

class TeamUnknownOptionTypeError(TeamError):
    pass

class TeamNetDeviceIndexNameConverter(object):
    """
    Class does conversion between various network device identificators.
    Note both functions have DeviceID as input parameter.
    That can be either: interface index (int)
                        interface name (str)
                        TeamNetDevice (or inheritor) instance
    """
    def __init__(self, th):
        self._th = th

    def get_ifindex(self, dev_id):
        """
        Get interface index.
        """
        if isinstance(dev_id, int):
            return dev_id
        elif isinstance(dev_id, TeamNetDevice):
            return dev_id.ifindex
        elif isinstance(dev_id, str):
            return capi.team_ifname2ifindex(self._th, dev_id)
        raise TeamError("Cannot convert to interface index.")

    def dev_ifname(self, dev_id):
        """
        Get interface name.
        """
        if isinstance(dev_id, str):
            return dev_id
        elif isinstance(dev_id, TeamNetDevice):
            ifindex = dev_id.ifindex
        elif isinstance(dev_id, int):
            ifindex = dev_id
        else:
            raise TeamError("Cannot convert to interface name.")
        return capi.team_ifindex2ifname(self._th, ifindex, 32)

class TeamNetDevice(object):
    """
    Class for manipulating generic network device.
    """
    def __init__(self, th, ifindex = 0):
        self._th = th
        self._conv = TeamNetDeviceIndexNameConverter(th)
        self.ifindex = ifindex

    def __str__(self):
        return self.ifname

    @property
    def ifindex(self):
        return self._ifindex

    @ifindex.setter
    def ifindex(self, ifindex):
        self._ifindex = ifindex
        if self.ifindex:
            self.ifname = self._conv.dev_ifname(ifindex)

    def get_hwaddr(self):
        err, hwaddr = capi.team_hwaddr_get(self._th, self.ifindex, 6)
        if err:
            raise TeamLibError("Failed to get hardware address", err)
        return ":".join(map(lambda x: "%02X" % x, struct.unpack('BBBBBB', hwaddr)))

    def set_hwaddr(self, hwaddr_str):
        pack = struct.pack('BBBBBB', *map(lambda x : int(x, 16), hwaddr_str.split(":")))
        err = capi.team_hwaddr_set(self._th, self.ifindex, pack)
        if err:
            raise TeamLibError("Failed to set hardware address", err)

class TeamPort(TeamNetDevice):
    """
    Class stores port data and serves for port modification.
    """
    def update(self, lib_port):
        """
        Update option by give library structure.
        """
        self.speed = capi.team_get_port_speed(lib_port)
        self.duplex = capi.team_get_port_duplex(lib_port)
        self.changed = capi.team_is_port_changed(lib_port)
        self.linkup = capi.team_is_port_link_up(lib_port)
        self.removed = capi.team_is_port_removed(lib_port)

class TeamPortListIterator(object):
    """
    Iterator class for TeamPortList class for iterating over all listed ports.
    """
    def __init__(self, ports):
        self._ports = ports
        self._cursor = 0

    def __iter__(self):
        iter

    def next(self):
        """ Get next item in dict """
        if self._cursor == len(self._ports):
            raise StopIteration
        else:
            key = self._ports.keys()[self._cursor]
            self._cursor += 1
            return self._ports[key]

class TeamPortList(object):
    """
    Class contains list of ports present on team. Dictionary is used
    internaly since port interface index is unique.
    """
    def __init__(self, th):
        self._th = th
        self._conv = TeamNetDeviceIndexNameConverter(th)
        self._ports = {}
        self.update()

    def __len__(self):
        return len(self._ports)

    def __iter__(self):
        return TeamPortListIterator(self._ports)

    def get_port(self, port_dev_id):
        """
        Get port instance identified by DeviceID.
        """
        return self._ports[self._conv.get_ifindex(port_dev_id)]

    def update(self):
        """
        Fetch fresh data from library and adjust update dictionary and port
        instances by it.
        """
        lib_port_ifindex_list = []
        lib_port = capi.team_get_next_port(self._th, None)
        while lib_port:
            ifindex = capi.team_get_port_ifindex(lib_port)
            lib_port_ifindex_list.append(ifindex)
            try:
                port = self.get_port(ifindex)
            except KeyError:
                port = TeamPort(self._th, ifindex)
                self._ports[ifindex] = port
            port.update(lib_port)
            lib_port = capi.team_get_next_port(self._th, lib_port)

        for ifindex in self._ports.keys():
            if not ifindex in lib_port_ifindex_list:
                del self._ports[ifindex]

class TeamOption(object):
    """
    Class stores option data and serves for value modification.
    """
    def __init__(self, th, name):
        self._th = th
        self.name = name

    def _get_option_value(self, lib_option):
        opt_type = capi.team_get_option_type(lib_option)
        if opt_type == capi.TEAM_OPTION_TYPE_U32:
            return capi.team_get_option_value_u32(lib_option)
        elif opt_type == capi.TEAM_OPTION_TYPE_STRING:
            return capi.team_get_option_value_string(lib_option)
        else:
            raise TeamUnknownOptionTypeError()

    def update(self, lib_option):
        """
        Update option by give library structure.
        """
        self.value = self._get_option_value(lib_option)
        self.changed = capi.team_is_option_changed(lib_option)

    def set_value(self, value):
        """
        Set option value.
        """
        if isinstance(value, int):
            err = capi.team_set_option_value_by_name_u32(self._th, self.name,
                                                         value)
        elif isinstance(value, str):
            err = capi.team_set_option_value_by_name_string(self._th,
                                                            self.name,
                                                            value)
        else:
            raise TeamUnknownOptionTypeError()
        if err:
            raise TeamLibError("Failed to set option", err)

class TeamOptionListIterator(object):
    """
    Iterator class for TeamOptionList class for iterating over all options.
    """
    def __init__(self, options):
        self._options = options
        self._cursor = 0

    def __iter__(self):
        iter

    def next(self):
        """ Get next item in dict """
        if self._cursor == len(self._options):
            raise StopIteration
        else:
            key = self._options.keys()[self._cursor]
            self._cursor += 1
            return self._options[key]

class TeamOptionList(object):
    """
    Class contains list of options present on team. Dictionary is used
    internaly since option name is unique.
    """
    def __init__(self, th):
        self._th = th
        self._options = {}
        self.update()

    def __len__(self):
        return len(self._options)

    def __iter__(self):
        return TeamOptionListIterator(self._options)

    def get_option(self, opt_name):
        """
        Get option instance identified by name.
        """
        return self._options[opt_name]

    def update(self):
        """
        Fetch fresh data from library and adjust update dictionary and option
        instances by it.
        """
        lib_option_name_list = []
        lib_option = capi.team_get_next_option(self._th, None)
        while lib_option:
            opt_name = capi.team_get_option_name(lib_option)
            lib_option_name_list.append(opt_name)
            try:
                option = self.get_option(opt_name)
            except KeyError:
                option = TeamOption(self._th, opt_name)
                self._options[opt_name] = option
            try:
                option.update(lib_option)
            except TeamUnknownOptionTypeError:
                del self._options[opt_name]
            lib_option = capi.team_get_next_option(self._th, lib_option)

        for opt_name in self._options.keys():
            if not opt_name in lib_option_name_list:
                del self._options[opt_name]

class TeamChangeHandler(object):
    def __init__(self, func, func_priv, type_mask):
        self._func = func
        self._func_priv = func_priv
        self._type_mask = type_mask

    def call(self, curr_type_mask):
        if self._type_mask & curr_type_mask:
            return self._func(self._func_priv)
        else:
            return 0

class TeamChangeHandlerList(object):
    def __init__(self):
        self._list = []

    def add(self, handler):
        if handler in self._list:
            raise TeamError("Failed to register change handler. Handler is already registered.")
        self._list.append(handler)

    def remove(self, handler):
        if not handler in self._list:
            raise TeamError("Failed to unregister change handler. Handler is not registered.")
        self._list.remove(handler)

    def call(self, type_mask):
        for handler in self._list:
            ret = handler.call(type_mask)
            if ret != 0:
                return ret


class Team(TeamNetDevice):
    """
    Class representing one team device instance.
    Paramaters passed to constructor allows:
        create == True ... Create new team device if it does not already exist.
        recreate == True ... Same as create but in case device exists already,
                             it's removed first.
        destroy == True ... Remove team device in close function.
    """
    def __init__(self, teamdev, create = False, recreate = False, destroy = False):
        th = capi.team_alloc()
        if not th:
            raise TeamLibError("Failed to allocate team handle.")

        super(Team, self).__init__(th)

        if isinstance(teamdev, str):
            err = 0
            if recreate:
                err = capi.team_recreate(th, teamdev)
            elif create:
                err = capi.team_create(th, teamdev)
            if err:
                raise TeamLibError("Failed to create team.", err)

        ifindex = self._conv.get_ifindex(teamdev) if teamdev else 0
        err = capi.team_init(th, ifindex)
        if err:
            raise TeamLibError("Failed to init team.", err)

        self.ifindex = ifindex
        self._destroy = destroy
        self._change_handler_list = TeamChangeHandlerList()
        self._port_list = TeamPortList(th)
        self._option_list = TeamOptionList(th)

        self._change_handler = capi.team_change_handler(self._change_handler_func,
                                                        TEAM_ANY_CHANGE)
        capi.py_team_change_handler_register(self._th, self._change_handler, None)


    def close(self):
        """
        Do class cleanup
        """
        if self._destroy:
            err = capi.team_destroy(self._th)
            if err:
                raise TeamLibError("Failed to destroy team.", err)

        capi.py_team_change_handler_unregister(self._th,
                                               self._change_handler, None)
        capi.team_free(self._th)

    def kill_loop(self):
        self._kill_loop = True

    def loop_forever(self):
        self._kill_loop = False
        fd = capi.team_get_event_fd(self._th)
        while True:
            try:
                ret = select.select([fd], [], [])
                if fd in ret[0]:
                    capi.team_handle_events(self._th)
            except KeyboardInterrupt:
                return
            except select.error as e:
                if e[0] == 4:
                    if self._kill_loop:
                        return
            except:
                raise

    def check_events(self):
        capi.team_check_events(self._th)

    def _change_handler_func(self, func_priv, type_mask):
        if type_mask & TEAM_PORT_CHANGE:
            self._port_list.update()
        if type_mask & TEAM_OPTION_CHANGE:
            self._option_list.update()
        self._change_handler_list.call(type_mask)

    def change_handler_register(self, change_handler):
        self._change_handler_list.add(change_handler)

    def change_handler_unregister(self, change_handler):
        self._change_handler_list.remove(change_handler)

    def get_mode_name(self):
        err, name = capi.team_get_mode_name(self._th)
        if err:
            raise TeamLibError("Failed to get mode name.", err)
        return name

    def set_mode_name(self, name):
        err = capi.team_set_mode_name(self._th, name)
        if err:
            raise TeamLibError("Failed to set mode name.", err)

    def get_active_port(self):
        err, port_ifindex = capi.team_get_active_port(self._th)
        if err:
            raise TeamLibError("Failed to get active port.", err)
        return self.get_port(port_ifindex)

    def set_active_port(self, dev_port_id):
        err = capi.team_set_active_port(self._th,
                                        self._conv.get_ifindex(dev_port_id))
        if err:
            raise TeamLibError("Failed to set active port.", err)

    def port_list(self):
        return self._port_list

    def get_port(self, port_dev_id):
        return self._port_list.get_port(port_dev_id)

    def port_add(self, port_dev_id):
        err = capi.team_port_add(self._th,
                                 self._conv.get_ifindex(port_dev_id))
        if err:
            raise TeamLibError("Failed to add port.", err)

    def port_remove(self, port_dev_id):
        err = capi.team_port_remove(self._th,
                                    self._conv.get_ifindex(port_dev_id))
        if err:
            raise TeamLibError("Failed to remove port.", err)

    def option_list(self):
        return self._option_list

    def get_option(self, opt_name):
        return self._option_list.get_option(opt_name)
