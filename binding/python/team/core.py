import capi
import select

def dev_ifindex(dev):
    if isinstance(dev, int):
        return dev
    return capi.team_ifname2ifindex(dev)

def dev_ifname(dev):
    if isinstance(dev, str):
        return dev
    return capi.team_ifindex2ifname(dev, 32)

TEAM_ALL_CHANGE = capi.TEAM_ALL_CHANGE
TEAM_PORT_CHANGE = capi.TEAM_PORT_CHANGE
TEAM_OPTION_CHANGE = capi.TEAM_OPTION_CHANGE

class team:
    def __init__(self, teamdev):
        self.__th = capi.team_alloc()
        err = capi.team_init(self.__th, dev_ifindex(teamdev))
        if err:
            raise Exception("Failed to init team. Err = %d" % err)
        self.__change_handlers = {}

    def __del__(self):
        capi.team_free(self.__th)

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
            raise Exception("Failed to register change handler. Function is already registered.")
        handler = capi.team_change_handler(func, priv, evtype)
        capi.py_team_change_handler_register(self.__th, handler)
        self.__change_handlers[func] = handler

    def change_handler_unregister(self, func):
        if not func in self.__change_handlers:
            raise Exception("Failed to unregister change handler. Function is not registered.")
        handler = self.__change_handlers[func]
        capi.py_team_change_handler_unregister(self.__th, handler)
        del(self.__change_handlers[func])

    def get_mode_name(self):
        err, name = capi.team_get_mode_name(self.__th)
        if err:
            raise Exception("Failed to get mode name. Err = %d" % err)
        return name

    def set_mode_name(self, name):
        err = capi.team_set_mode_name(self.__th, name)
        if err:
            raise Exception("Failed to set mode name. Err = %d" % err)

    def get_active_port(self):
        err, port_ifindex = capi.team_get_active_port(self.__th)
        if err:
            raise Exception("Failed to get active port. Err = %d" % err)
        return (port_ifindex, dev_ifname(port_ifindex))

    def set_active_port(self, port):
        err = capi.team_set_active_port(self.__th, dev_ifindex(port))
        if err:
            raise Exception("Failed to set active port. Err = %d" % err)

    def port_list(self):
        port = None
        port_list = []
        port = capi.team_get_next_port(self.__th, None)
        while port:
            port_item = {}
            port_item["ifindex"] = port.ifindex
            port_item["ifname"] = dev_ifname(port.ifindex)
            port_item["speed"] = port.speed
            port_item["duplex"] = port.duplex
            port_item["changed"] = port.changed
            port_item["linkup"] = port.linkup
            port_list.append(port_item)
            port = capi.team_get_next_port(self.__th, port)
        return port_list
