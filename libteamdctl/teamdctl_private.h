/*
 *   teamdctl_private.h - Teamd daemon control library private header
 *   Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
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

#ifndef _TEAMDCTL_PRIVATE_H_
#define _TEAMDCTL_PRIVATE_H_

#include <syslog.h>
#include <teamdctl.h>

#define TEAMDCTL_EXPORT __attribute__ ((visibility("default")))

/**
 * SECTION: teamdctl
 * @short_description: libteamdctl context
 */

struct teamdctl_cli;

struct teamdctl {
	void (*log_fn)(struct teamdctl *tdc, int priority,
		       const char *file, int line, const char *fn,
		       const char *format, va_list args);
	int log_priority;
	const struct teamdctl_cli *cli;
	void *cli_priv;
};

/**
 * SECTION: logging
 * @short_description: libteamdctl logging facility
 */

void teamdctl_log(struct teamdctl *tdc, int priority,
		  const char *file, int line, const char *fn,
		  const char *format, ...);

static inline void __attribute__((always_inline, format(printf, 2, 3)))
teamdctl_log_null(struct teamdctl *tdc, const char *format, ...) {}

#define teamdctl_log_cond(tdc, prio, arg...)				\
	do {								\
		if (teamdctl_get_log_priority(tdc) >= prio)		\
			teamdctl_log(tdc, prio, __FILE__, __LINE__,	\
				  __FUNCTION__, ## arg);		\
	} while (0)

#ifdef ENABLE_LOGGING
#  ifdef ENABLE_DEBUG
#    define dbg(tdc, arg...) teamdctl_log_cond(tdc, LOG_DEBUG, ## arg)
#  else
#    define dbg(tdc, arg...) teamdctl_log_null(tdc, ## arg)
#  endif
#  define info(tdc, arg...) teamdctl_log_cond(tdc, LOG_INFO, ## arg)
#  define warn(tdc, arg...) teamdctl_log_cond(tdc, LOG_WARNING, ## arg)
#  define err(tdc, arg...) teamdctl_log_cond(tdc, LOG_ERR, ## arg)
#else
#  define dbg(tdc, arg...) teamdctl_log_null(tdc, ## arg)
#  define info(tdc, arg...) teamdctl_log_null(tdc, ## arg)
#  define warn(tdc, arg...) teamdctl_log_null(tdc, ## arg)
#  define err(tdc, arg...) teamdctl_log_null(tdc, ## arg)
#endif

struct teamdctl_cli {
	const char *name;
	size_t priv_size;
	int (*init)(struct teamdctl *tdc, const char *team_name, void *priv);
	void (*fini)(struct teamdctl *tdc, void *priv);
	int (*method_call)(struct teamdctl *tdc, const char *method_name,
			   char **p_reply, void *priv,
			   const char *fmt, va_list ap);
};

/* Cli structures */
const struct teamdctl_cli teamdctl_cli_usock;
const struct teamdctl_cli teamdctl_cli_dbus;

#endif /* _TEAMDCTL_PRIVATE_H_ */
