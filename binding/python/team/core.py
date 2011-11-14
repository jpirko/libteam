import capi
import select

TEAM_ALL_CHANGE = capi.TEAM_ALL_CHANGE
TEAM_PORT_CHANGE = capi.TEAM_PORT_CHANGE
TEAM_OPTION_CHANGE = capi.TEAM_OPTION_CHANGE

class TeamError(Exception):
    pass

class TeamLibError(TeamError):
    def __init__(self, msg, err = 0):
        self.__msg = msg
        self.__err = err

    def __str__(self):
        msg = self.__msg
        if self.__err:
            msg += " Err=%d" % self.__err
        return msg

class TeamUnknownOptionTypeError(TeamError):
    pass

class team:
    def __init__(self, teamdev, create = False, recreate = False):
        self.__th = capi.team_alloc()
        if not self.__th:
            raise TeamLibError("Failed to allocate team handle.")

        if isinstance(teamdev, str):
            err = 0
            if recreate:
                err = capi.team_recreate(self.__th, teamdev)
            elif create:
                err = capi.team_create(self.__th, teamdev)
            if err:
                raise TeamLibError("Failed to create team.", err)

        ifindex = self.__dev_ifindex(teamdev) if teamdev else 0
        err = capi.team_init(self.__th, ifindex)
        if err:
            raise TeamLibError("Failed to init team.", err)
        self.__change_handlers = {}

    def __del__(self):
        capi.team_free(self.__th)

    def __dev_ifindex(self, dev):
        if isinstance(dev, int):
            return dev
        return capi.team_ifname2ifindex(self.__th, dev)

    def __dev_ifname(self, dev):
        if isinstance(dev, str):
            return dev
        return capi.team_ifindex2ifname(self.__th, dev, 32)

    def loop_forever(self):
        fd = self.get_event_fd()
        try:
            while True:
                ret = select.select([fd],[],[])
                if fd in ret[0]:
                    self.process_event()
        except KeyboardInterrupt:
            pass
        except:
            raise

    def get_event_fd(self):
        return capi.team_get_event_fd(self.__th)

    def process_event(self):
        capi.team_process_event(self.__th)

    def check_events(self):
        capi.team_check_events(self.__th)

    def change_handler_register(self, func, priv, evtype):
        if func in self.__change_handlers:
            raise TeamError("Failed to register change handler. Function is already registered.")
        handler = capi.team_change_handler(func, priv, evtype)
        capi.py_team_change_handler_register(self.__th, handler)
        self.__change_handlers[func] = handler

    def change_handler_unregister(self, func):
        if not func in self.__change_handlers:
            raise TeamError("Failed to unregister change handler. Function is not registered.")
        handler = self.__change_handlers[func]
        capi.py_team_change_handler_unregister(self.__th, handler)
        del(self.__change_handlers[func])

    def get_mode_name(self):
        err, name = capi.team_get_mode_name(self.__th)
        if err:
            raise TeamLibError("Failed to get mode name.", err)
        return name

    def set_mode_name(self, name):
        err = capi.team_set_mode_name(self.__th, name)
        if err:
            raise TeamLibError("Failed to set mode name.", err)

    def get_active_port(self):
        err, port_ifindex = capi.team_get_active_port(self.__th)
        if err:
            raise TeamLibError("Failed to get active port.", err)
        return (port_ifindex, self.__dev_ifname(port_ifindex))

    def set_active_port(self, port):
        err = capi.team_set_active_port(self.__th, self.__dev_ifindex(port))
        if err:
            raise TeamLibError("Failed to set active port.", err)

    def port_list(self):
        port_list = []
        port = capi.team_get_next_port(self.__th, None)
        while port:
            port_item = {}
            ifindex = capi.team_get_port_ifindex(port)
            port_item["ifindex"] = ifindex
            port_item["ifname"] = self.__dev_ifname(ifindex)
            port_item["speed"] = capi.team_get_port_speed(port)
            port_item["duplex"] = capi.team_get_port_duplex(port)
            port_item["changed"] = capi.team_is_port_changed(port)
            port_item["linkup"] = capi.team_is_port_link_up(port)
            port_list.append(port_item)
            port = capi.team_get_next_port(self.__th, port)
        return port_list

    def __get_option_value(self, option):
        opt_type = capi.team_get_option_type(option)
        if opt_type == capi.TEAM_OPTION_TYPE_U32:
            return capi.team_get_option_value_u32(option)
        elif opt_type == capi.TEAM_OPTION_TYPE_STRING:
            return capi.team_get_option_value_string(option)
        else:
            raise TeamUnknownOptionTypeError()

    def get_option_value(self, opt_name):
        option = capi.team_get_option_by_name(self.__th, opt_name)
        if not option:
            raise TeamLibError("Failed to get option")
        return self.__get_option_value(option)

    def set_option_value(self, opt_name, opt_value):
        if isinstance(opt_value, int):
            err = capi.team_set_option_value_by_name_u32(self.__th, opt_name,
                                                         opt_value)
        elif isinstance(opt_value, str):
            err = capi.team_set_option_value_by_name_string(self.__th,
                                                            opt_name,
                                                            opt_value)
        else:
            raise TeamUnknownOptionTypeError()
        if err:
            raise TeamLibError("Failed to set option", err)

    def option_list(self):
        option_list = {}
        option = capi.team_get_next_option(self.__th, None)
        while option:
            option_item = {}
            option_item["changed"] = capi.team_is_option_changed(option)
            try:
                option_item["value"] = self.__get_option_value(option)
                option_name = capi.team_get_option_name(option)
                option_list[option_name] = option_item
            except TeamUnknownOptionTypeError:
                continue
            finally:
                option = capi.team_get_next_option(self.__th, option)
        return option_list

    def port_add(self, port):
        err = capi.team_port_add(self.__th, self.__dev_ifindex(port))
        if err:
            raise TeamLibError("Failed to add port.", err)

    def port_remove(self, port):
        err = capi.team_port_remove(self.__th, self.__dev_ifindex(port))
        if err:
            raise TeamLibError("Failed to remove port.", err)
