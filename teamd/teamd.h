/*
 *   teamd.h - Network team device daemon
 *   Copyright (C) 2011 Jiri Pirko <jpirko@redhat.com>
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

#ifndef _TEAMD_H_
#define _TEAMD_H_

#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <libdaemon/dlog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <assert.h>
#include <jansson.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <team.h>
#include <private/list.h>

#include "config.h"

#ifdef ENABLE_DBUS
#include <dbus/dbus.h>
#endif

#ifdef ENABLE_ZMQ
#include <zmq.h>
#endif

#define teamd_log_err(args...) daemon_log(LOG_ERR, ##args)
#define teamd_log_warn(args...) daemon_log(LOG_WARNING, ##args)
#define teamd_log_info(args...) daemon_log(LOG_INFO, ##args)
#define teamd_log_dbg(args...) daemon_log(LOG_DEBUG, ##args)

#define teamd_log_dbgx(ctx, val, args...)	\
	if (val <= ctx->debug)			\
		daemon_log(LOG_DEBUG, ##args)

static inline void TEAMD_BUG(void)
{
	teamd_log_dbg("BUG: %s:%d\n", __FILE__, __LINE__);
	assert(0);
}

static inline void TEAMD_BUG_ON(bool condition)
{
	if (condition)
		TEAMD_BUG();
}

#define TEAMD_RUN_DIR "/var/run/teamd/"

static inline int teamd_make_rundir(void)
{
	int ret;

	ret = mkdir(TEAMD_RUN_DIR, 0755);
	if (ret && errno != EEXIST) {
		teamd_log_err("Failed to create directory \"%s\"",
			      TEAMD_RUN_DIR);
		return -errno;
	}
	return 0;
}

enum teamd_command {
	DAEMON_CMD_RUN,
	DAEMON_CMD_KILL,
	DAEMON_CMD_VERSION,
	DAEMON_CMD_HELP,
	DAEMON_CMD_CHECK
};

struct teamd_runner;
struct teamd_context;

struct teamd_context {
	enum teamd_command		cmd;
	bool				daemonize;
	unsigned int			debug;
	bool				force_recreate;
	bool				init_no_ports;
	char *				config_file;
	char *				config_text;
	json_t *			config_json;
	char *				pid_file;
	char *				team_devname;
	char *				ident;
	char *				argv0;
	struct team_handle *		th;
	const struct teamd_runner *	runner;
	void *				runner_priv;
	struct list_item		port_obj_list;
	unsigned int			port_obj_list_count;
	struct list_item                option_watch_list;
	struct list_item		event_watch_list;
	struct list_item		state_ops_list;
	struct list_item		state_val_list;
	uint32_t			ifindex;
	struct team_ifinfo *		ifinfo;
	char *				hwaddr;
	uint32_t			hwaddr_len;
	struct {
		struct list_item		callback_list;
		int				ctrl_pipe_r;
		int				ctrl_pipe_w;
		int				err;
	} run_loop;
#ifdef ENABLE_DBUS
	struct {
		bool			enabled;
		DBusConnection *	con;
	} dbus;
#endif
#ifdef ENABLE_ZMQ
	struct {
		bool			enabled;
		void *			context;
		void *			sock;
		char *			addr;
	} zmq;
#endif
	struct {
		bool			enabled;
		int			sock;
		struct sockaddr_un	addr;
		struct list_item	acc_conn_list;
	} usock;
	struct {
		struct list_item	work_list;
		int			pipe_r;
		int			pipe_w;
	} workq;
};

struct teamd_port {
	uint32_t			ifindex;
	char *				ifname;
	struct team_port *		team_port;
	struct team_ifinfo *		team_ifinfo;
};

struct teamd_runner {
	const char *name;
	const char *team_mode_name;
	size_t priv_size;
	int (*init)(struct teamd_context *ctx, void *priv);
	void (*fini)(struct teamd_context *ctx, void *priv);
};

struct teamd_event_watch_ops {
	int (*hwaddr_changed)(struct teamd_context *ctx, void *priv);
	int (*ifname_changed)(struct teamd_context *ctx, void *priv);
	int (*port_added)(struct teamd_context *ctx,
			  struct teamd_port *tdport, void *priv);
	void (*port_removed)(struct teamd_context *ctx,
			     struct teamd_port *tdport, void *priv);
	int (*port_changed)(struct teamd_context *ctx,
			      struct teamd_port *tdport, void *priv);
	int (*port_link_changed)(struct teamd_context *ctx,
				 struct teamd_port *tdport, void *priv);
	int (*port_hwaddr_changed)(struct teamd_context *ctx,
				   struct teamd_port *tdport, void *priv);
	int (*port_ifname_changed)(struct teamd_context *ctx,
				   struct teamd_port *tdport, void *priv);
	int (*option_changed)(struct teamd_context *ctx,
			      struct team_option *option, void *priv);
	char *option_changed_match_name;
};

int teamd_event_port_added(struct teamd_context *ctx,
			   struct teamd_port *tdport);
void teamd_event_port_removed(struct teamd_context *ctx,
			      struct teamd_port *tdport);
int teamd_event_port_changed(struct teamd_context *ctx,
			     struct teamd_port *tdport);
int teamd_event_port_link_changed(struct teamd_context *ctx,
				  struct teamd_port *tdport);
int teamd_event_option_changed(struct teamd_context *ctx,
			       struct team_option *option);
int teamd_event_ifinfo_hwaddr_changed(struct teamd_context *ctx,
				      struct team_ifinfo *ifinfo);
int teamd_event_ifinfo_ifname_changed(struct teamd_context *ctx,
				      struct team_ifinfo *ifinfo);
int teamd_events_init(struct teamd_context *ctx);
void teamd_events_fini(struct teamd_context *ctx);
int teamd_event_watch_register(struct teamd_context *ctx,
			       const struct teamd_event_watch_ops *ops,
			       void *priv);
void teamd_event_watch_unregister(struct teamd_context *ctx,
				  const struct teamd_event_watch_ops *ops,
				  void *priv);

/* Main loop callbacks */
#define TEAMD_LOOP_FD_EVENT_READ	(1 << 0)
#define TEAMD_LOOP_FD_EVENT_WRITE	(1 << 1)
#define TEAMD_LOOP_FD_EVENT_EXCEPTION	(1 << 2)
#define TEAMD_LOOP_FD_EVENT_MASK	(TEAMD_LOOP_FD_EVENT_READ | \
					 TEAMD_LOOP_FD_EVENT_WRITE | \
					 TEAMD_LOOP_FD_EVENT_EXCEPTION)

typedef int (*teamd_loop_callback_func_t)(struct teamd_context *ctx,
					  int events, void *priv);

int teamd_loop_callback_fd_add(struct teamd_context *ctx,
			       const char *cb_name, void *priv,
			       teamd_loop_callback_func_t func,
			       int fd, int fd_event);
int teamd_loop_callback_timer_add_set(struct teamd_context *ctx,
				      const char *cb_name, void *priv,
				      teamd_loop_callback_func_t func,
				      struct timespec *interval,
				      struct timespec *initial);
int teamd_loop_callback_timer_add(struct teamd_context *ctx,
				  const char *cb_name, void *priv,
				  teamd_loop_callback_func_t func);
int teamd_loop_callback_timer_set(struct teamd_context *ctx,
				  const char *cb_name, void *priv,
				  struct timespec *interval,
				  struct timespec *initial);
void teamd_loop_callback_del(struct teamd_context *ctx, const char *cb_name,
			     void *priv);
int teamd_loop_callback_enable(struct teamd_context *ctx, const char *cb_name,
			       void *priv);
int teamd_loop_callback_disable(struct teamd_context *ctx, const char *cb_name,
				void *priv);
void teamd_run_loop_restart(struct teamd_context *ctx);

/* Runner structures */
extern const struct teamd_runner teamd_runner_broadcast;
extern const struct teamd_runner teamd_runner_roundrobin;
extern const struct teamd_runner teamd_runner_random;
extern const struct teamd_runner teamd_runner_activebackup;
extern const struct teamd_runner teamd_runner_loadbalance;
extern const struct teamd_runner teamd_runner_lacp;

struct teamd_port_priv {
	int (*init)(struct teamd_context *ctx, struct teamd_port *tdport,
		    void *this_priv, void *creator_priv);
	void (*fini)(struct teamd_context *ctx, struct teamd_port *tdport,
		     void *this_priv, void *creator_priv);
	size_t priv_size;
};

int teamd_port_priv_create_and_get(void **ppriv, struct teamd_port *tdport,
				   const struct teamd_port_priv *pp,
				   void *creator_priv);
int teamd_port_priv_create(struct teamd_port *tdport,
			   const struct teamd_port_priv *pp, void *creator_priv);
void *teamd_get_next_port_priv_by_creator(struct teamd_port *tdport,
					  void *creator_priv, void *priv);
void *teamd_get_first_port_priv_by_creator(struct teamd_port *tdport,
					   void *creator_priv);
#define teamd_for_each_port_priv_by_creator(priv, tdport, creator_priv)		\
	for (priv = teamd_get_next_port_priv_by_creator(tdport, creator_priv,	\
							NULL);			\
	     priv;								\
	     priv = teamd_get_next_port_priv_by_creator(tdport,	creator_priv,	\
							priv))

int teamd_per_port_init(struct teamd_context *ctx);
void teamd_per_port_fini(struct teamd_context *ctx);
struct teamd_port *teamd_get_port(struct teamd_context *ctx, uint32_t ifindex);
struct teamd_port *teamd_get_port_by_ifname(struct teamd_context *ctx,
					    char *ifname);
struct teamd_port *teamd_get_next_tdport(struct teamd_context *ctx,
					 struct teamd_port *tdport);
#define teamd_for_each_tdport(tdport, ctx)				\
	for (tdport = teamd_get_next_tdport(ctx, NULL); tdport;		\
	     tdport = teamd_get_next_tdport(ctx, tdport))
static inline bool teamd_has_ports(struct teamd_context *ctx)
{
	return !list_empty(&ctx->port_obj_list);
}

static inline unsigned int teamd_port_count(struct teamd_context *ctx)
{
	return ctx->port_obj_list_count;
}

int teamd_port_add(struct teamd_context *ctx, const char *port_name);
int teamd_port_remove(struct teamd_context *ctx, const char *port_name);
int teamd_port_enabled(struct teamd_context *ctx, struct teamd_port *tdport,
		       bool *enabled);
int teamd_port_prio(struct teamd_context *ctx, struct teamd_port *tdport);

static inline bool teamd_port_present(struct teamd_context *ctx,
				      struct teamd_port *tdport)
{
	return team_is_port_present(ctx->th, tdport->team_port);
}

bool teamd_link_watch_port_up(struct teamd_context *ctx,
			      struct teamd_port *tdport);
void teamd_link_watches_set_forced_active(struct teamd_context *ctx,
					  bool forced_active);
int teamd_link_watch_init(struct teamd_context *ctx);
void teamd_link_watch_fini(struct teamd_context *ctx);

int teamd_option_watch_init(struct teamd_context *ctx);
void teamd_option_watch_fini(struct teamd_context *ctx);

int teamd_ifinfo_watch_init(struct teamd_context *ctx);
void teamd_ifinfo_watch_fini(struct teamd_context *ctx);

struct teamd_balancer;
int teamd_balancer_init(struct teamd_context *ctx, struct teamd_balancer **ptb);
void teamd_balancer_fini(struct teamd_balancer *tb);
int teamd_balancer_port_added(struct teamd_balancer *tb,
			      struct teamd_port *tdport);
void teamd_balancer_port_removed(struct teamd_balancer *tb,
				 struct teamd_port *tdport);

int teamd_hash_func_set(struct teamd_context *ctx);

int teamd_packet_sock_open(int *sock_p, const uint32_t ifindex,
			   const unsigned short family,
			   const struct sock_fprog *fprog,
			   const struct sock_fprog *alt_fprog);
int teamd_getsockname_hwaddr(int sock, struct sockaddr_ll *addr,
			     size_t expected_len);
int teamd_sendto(int sockfd, const void *buf, size_t len, int flags,
		 const struct sockaddr *dest_addr, socklen_t addrlen);
int teamd_recvfrom(int sockfd, void *buf, size_t len, int flags,
		   struct sockaddr *src_addr, socklen_t addrlen);

/* Various helpers */
static inline void ms_to_timespec(struct timespec *ts, int ms)
{
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000000;
}

static inline int timespec_to_ms(struct timespec *ts)
{
	return ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
}

static inline bool timespec_is_zero(struct timespec *ts)
{
	return !ts->tv_sec && !ts->tv_nsec;
}

#endif /* _TEAMD_H_ */
