/*
 *   teamdctl.h - Teamd daemon control library
 *   Copyright (C) 2013-2015 Jiri Pirko <jiri@resnulli.us>
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _TEAMDCTL_H_
#define _TEAMDCTL_H_

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * teamdctl
 *
 * library user context
 */
struct teamdctl;

struct teamdctl *teamdctl_alloc(void);
void teamdctl_free(struct teamdctl *tdc);
void teamdctl_set_log_fn(struct teamdctl *tdc,
			 void (*log_fn)(struct teamdctl *tdc, int priority,
					const char *file, int line,
					const char *fn, const char *format,
					va_list args));
int teamdctl_get_log_priority(struct teamdctl *tdc);
void teamdctl_set_log_priority(struct teamdctl *tdc, int priority);
int teamdctl_connect(struct teamdctl *tdc, const char *team_name,
		     const char *addr, const char *cli_type);
void teamdctl_disconnect(struct teamdctl *tdc);
int teamdctl_refresh(struct teamdctl *tdc);
int teamdctl_port_add(struct teamdctl *tdc, const char *port_devname);
int teamdctl_port_remove(struct teamdctl *tdc, const char *port_devname);
int teamdctl_port_config_update_raw(struct teamdctl *tdc,
				    const char *port_devname,
				    const char *port_config_raw);
int teamdctl_port_config_get_raw_direct(struct teamdctl *tdc,
					const char *port_devname,
					char **p_cfg);
char *teamdctl_config_get_raw(struct teamdctl *tdc);
int teamdctl_config_get_raw_direct(struct teamdctl *tdc, char **p_cfg);
char *teamdctl_config_actual_get_raw(struct teamdctl *tdc);
int teamdctl_config_actual_get_raw_direct(struct teamdctl *tdc, char **p_cfg);
char *teamdctl_state_get_raw(struct teamdctl *tdc);
int teamdctl_state_get_raw_direct(struct teamdctl *tdc, char **p_cfg);
int teamdctl_state_item_value_get(struct teamdctl *tdc, const char *item_path,
				  char **p_value);
int teamdctl_state_item_value_set(struct teamdctl *tdc, const char *item_path,
				  const char *value);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _TEAMDCTL_H_ */
