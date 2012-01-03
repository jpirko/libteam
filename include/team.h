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

/*
 * team_handle
 *
 * library user context
 */
struct team_handle;

struct team_handle *team_alloc(void);
int team_create(struct team_handle *th, const char *team_name);
int team_recreate(struct team_handle *th, const char *team_name);
int team_destroy(struct team_handle *th);
int team_init(struct team_handle *th, uint32_t ifindex);
void team_free(struct team_handle *th);
void team_set_log_fn(struct team_handle *th,
		     void (*log_fn)(struct team_handle *th, int priority,
				    const char *file, int line, const char *fn,
				    const char *format, va_list args));
int team_get_log_priority(struct team_handle *th);
void team_set_log_priority(struct team_handle *th, int priority);
int team_get_event_fd(struct team_handle *th);
void team_process_event(struct team_handle *th);
void team_check_events(struct team_handle *th);
int team_get_mode_name(struct team_handle *th, char **mode_name);
int team_set_mode_name(struct team_handle *th, const char *mode_name);
int team_get_active_port(struct team_handle *th, uint32_t *ifindex);
int team_set_active_port(struct team_handle *th, uint32_t ifindex);

/*
 * team_port
 *
 * access to port_list and individual port
 */
struct team_port;

struct team_port *team_get_next_port(struct team_handle *th,
				     struct team_port *port);
#define team_for_each_port(port, th)				\
	for (port = team_get_next_port(th, NULL); port;		\
	     port = team_get_next_port(th, port))
/* port getters */
uint32_t team_get_port_ifindex(struct team_port *port);
uint32_t team_get_port_speed(struct team_port *port);
uint8_t team_get_port_duplex(struct team_port *port);
bool team_is_port_link_up(struct team_port *port);
bool team_is_port_changed(struct team_port *port);

/*
 * team_option
 *
 * access to option_list and individual option
 */
struct team_port;

enum team_option_type {
	TEAM_OPTION_TYPE_U32,
	TEAM_OPTION_TYPE_STRING,
};

struct team_option;

struct team_option *team_get_option_by_name(struct team_handle *th,
					    const char *name);
struct team_option *team_get_next_option(struct team_handle *th,
					 struct team_option *option);
#define team_for_each_option(port, th)				\
	for (option = team_get_next_option(th, NULL); option;	\
	     option = team_get_next_option(th, option))
/* option getters */
char *team_get_option_name(struct team_option *option);
enum team_option_type team_get_option_type(struct team_option *option);
uint32_t team_get_option_value_u32(struct team_option *option);
char *team_get_option_value_string(struct team_option *option);
bool team_is_option_changed(struct team_option *option);
int team_get_option_value_by_name_u32(struct team_handle *th,
				      const char *name, uint32_t *u32_ptr);
int team_get_option_value_by_name_string(struct team_handle *th,
					 const char *name, char **str_ptr);
/* option setters */
int team_set_option_value_by_name_u32(struct team_handle *th,
				      const char *name, uint32_t val);
int team_set_option_value_by_name_string(struct team_handle *th,
					 const char *name, const char *str);

/*
 * team_change_handler
 *
 * define change event types and register change handler functions
 */
enum {
	TEAM_PORT_CHANGE	= 0x1,
	TEAM_OPTION_CHANGE	= 0x2,
	TEAM_ANY_CHANGE		= TEAM_PORT_CHANGE | TEAM_OPTION_CHANGE,
};

typedef unsigned int team_change_type_mask_t;

struct team_change_handler {
	void			(*func)(struct team_handle *th,
					void *func_priv,
					team_change_type_mask_t type_mask);
					/* type_mask passed to function
					 * represents types of events which
					 * really happened. */
	void *			func_priv;
	team_change_type_mask_t	type_mask;
};

int team_change_handler_register(struct team_handle *th,
				 struct team_change_handler *handler);
void team_change_handler_unregister(struct team_handle *th,
				    struct team_change_handler *handler);

/*
 * route netlink helper functions
 */
uint32_t team_ifname2ifindex(struct team_handle *th, const char *ifname);
char *team_ifindex2ifname(struct team_handle *th, uint32_t ifindex,
			  char *ifname, unsigned int maxlen);
int team_port_add(struct team_handle *th, uint32_t port_ifindex);
int team_port_remove(struct team_handle *th, uint32_t port_ifindex);
int team_hwaddr_set(struct team_handle *th, uint32_t ifindex,
		    const char *addr, unsigned int addr_len);
int team_hwaddr_get(struct team_handle *th, uint32_t ifindex,
		    char *addr, unsigned int addr_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _TEAM_H_ */
