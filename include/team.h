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
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct team_handle;
struct team_port;

enum team_option_type {
	TEAM_OPTION_TYPE_U32,
	TEAM_OPTION_TYPE_STRING,
};

struct team_option;

#define team_for_each_port(port, th)				\
	for (port = team_get_next_port(th, NULL); port;		\
	     port = team_get_next_port(th, port))

#define team_for_each_option(port, th)				\
	for (option = team_get_next_option(th, NULL); option;	\
	     option = team_get_next_option(th, option))

enum team_change_type {
	TEAM_ALL_CHANGE,
	TEAM_PORT_CHANGE,
	TEAM_OPTION_CHANGE,
};

struct team_change_handler {
	void			(*func)(struct team_handle *, void *);
	void *			func_priv;
	enum team_change_type	type;
};

struct team_handle *team_alloc(void);
int team_init(struct team_handle *th, uint32_t ifindex);
void team_free(struct team_handle *th);
int team_get_event_fd(struct team_handle *th);
void team_process_event(struct team_handle *th);
void team_check_events(struct team_handle *th);
struct team_port *team_get_next_port(struct team_handle *th,
				     struct team_port *port);
struct team_option *team_get_next_option(struct team_handle *th,
					 struct team_option *option);
int team_change_handler_register(struct team_handle *th,
				 struct team_change_handler *handler);
void team_change_handler_unregister(struct team_handle *th,
				    struct team_change_handler *handler);

/* port getters */
uint32_t team_get_port_ifindex(struct team_port *port);
uint32_t team_get_port_speed(struct team_port *port);
uint8_t team_get_port_duplex(struct team_port *port);
bool team_is_port_changed(struct team_port *port);
bool team_is_port_link_up(struct team_port *port);

/* option getters/setters */
char *team_get_option_name(struct team_option *option);
enum team_option_type team_get_option_type(struct team_option *option);
bool team_is_option_changed(struct team_option *option);
struct team_option *team_get_option_by_name(struct team_handle *th, char *name);
uint32_t team_get_option_value_u32(struct team_option *option);
char *team_get_option_value_string(struct team_option *option);
int team_get_option_value_by_name_u32(struct team_handle *th,
				      char *name, uint32_t *u32_ptr);
int team_get_option_value_by_name_string(struct team_handle *th,
					 char *name, char **str_ptr);
int team_set_option_value_by_name_u32(struct team_handle *th,
				      char *opt_name, uint32_t val);
int team_set_option_value_by_name_string(struct team_handle *th,
					 char *opt_name, char *str);

int team_get_mode_name(struct team_handle *th, char **mode_name);
int team_set_mode_name(struct team_handle *th, char *mode_name);
int team_get_active_port(struct team_handle *th, uint32_t *ifindex);
int team_set_active_port(struct team_handle *th, uint32_t ifindex);

/* Route netlink helper function */
uint32_t team_ifname2ifindex(struct team_handle *th, const char *ifname);
char *team_ifindex2ifname(struct team_handle *th, uint32_t ifindex,
			  char *ifname, unsigned int maxlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _TEAM_H_ */
