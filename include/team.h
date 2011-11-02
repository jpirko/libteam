/*
 * team.h - Network team device driver library
 * Copyright (c) 2011 Jiri Pirko <jpirko@redhat.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation version 2.1 of the License.
 */

#ifndef _TEAM_H_
#define _TEAM_H_

#include <stdint.h>

struct __team_list_head {
	struct __team_list_head *next, *prev;
};

struct team_handle {
	struct nl_sock *	nl_sock;
	int			nl_sock_err;
	struct nl_sock *	nl_sock_event;
	int			family;
	uint32_t		ifindex;
	struct __team_list_head	port_list;
	struct __team_list_head	option_list;
	struct __team_list_head	change_handler_list;
	struct {
		struct nl_sock *	sock;
		struct nl_cache *	link_cache;
	} nl_cli;
};

struct team_port {
	struct __team_list_head	list;
	uint32_t		ifindex;
	uint32_t		speed;
	uint8_t			duplex;
	int			changed;
	int			linkup;
};

enum team_option_type {
	TEAM_OPTION_TYPE_U32,
	TEAM_OPTION_TYPE_STRING,
};

struct team_option {
	struct __team_list_head	list;
	int			type;
	int			changed;
	char *			name;
	void *			data;
};

#define team_for_each_port(port, th)				\
	for (port = team_get_next_port(th, NULL); port;		\
	     port = team_get_next_port(th, port))

#define team_for_each_option(port, th)				\
	for (option = team_get_next_option(th, NULL); option;	\
	     option = team_get_next_option(th, option))
#endif

enum team_change_type {
	TEAM_ALL_CHANGE,
	TEAM_PORT_CHANGE,
	TEAM_OPTION_CHANGE,
};

struct team_change_handler {
	struct __team_list_head	list;
	void			(*func)(struct team_handle *, void *);
	void *			data;
	enum team_change_type	type;
	char			call_this; /* bool */
};

extern struct team_handle *team_alloc(void);
extern int team_init(struct team_handle *th, uint32_t ifindex);
extern void team_free(struct team_handle *th);
extern int team_get_event_fd(struct team_handle *th);
extern void team_process_event(struct team_handle *th);
extern void team_check_events(struct team_handle *th);
extern struct team_port *team_get_next_port(struct team_handle *th,
					    struct team_port *port);
extern struct team_option *team_get_next_option(struct team_handle *th,
						struct team_option *option);
extern void team_change_handler_register(struct team_handle *th,
					 struct team_change_handler *handler);
extern void team_change_handler_unregister(struct team_handle *th,
					   struct team_change_handler *handler);
extern int team_get_mode_name(struct team_handle *th, char **mode_name);
extern int team_set_mode_name(struct team_handle *th, char *mode_name);
extern int team_get_active_port(struct team_handle *th, uint32_t *ifindex);
extern int team_set_active_port(struct team_handle *th, uint32_t ifindex);
extern uint32_t team_ifname2ifindex(struct team_handle *th,
				    const char *ifname);
extern char *team_ifindex2ifname(struct team_handle *th, uint32_t ifindex,
				 char *ifname, unsigned int maxlen);
