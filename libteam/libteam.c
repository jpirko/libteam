/*
 *   libteam.c - Network team device driver library
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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <time.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/link.h>
#include <linux/if_team.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <team.h>
#include <private/list.h>
#include <private/misc.h>
#include "team_private.h"

/**
 * SECTION: logging
 * @short_description: libteam logging facility
 */
void team_log(struct team_handle *th, int priority,
	      const char *file, int line, const char *fn,
	      const char *format, ...)
{
	va_list args;

	va_start(args, format);
	th->log_fn(th, priority, file, line, fn, format, args);
	va_end(args);
}

static void log_stderr(struct team_handle *th, int priority,
		       const char *file, int line, const char *fn,
		       const char *format, va_list args)
{
	fprintf(stderr, "libteam: %s: ", fn);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
}

static int log_priority(const char *priority)
{
	char *endptr;
	int prio;

	prio = strtol(priority, &endptr, 10);
	if (endptr[0] == '\0' || isspace(endptr[0]))
		return prio;
	if (strncmp(priority, "err", 3) == 0)
		return LOG_ERR;
	if (strncmp(priority, "info", 4) == 0)
		return LOG_INFO;
	if (strncmp(priority, "debug", 5) == 0)
		return LOG_DEBUG;
	return 0;
}

/**
 * SECTION: libnl helpers
 * @short_description: various libnl helper functions
 */

int nl2syserr(int nl_error)
{
	switch (abs(nl_error)) {
	case 0:				return 0;
	case NLE_EXIST:			return EEXIST;
	case NLE_NOADDR:		return EADDRNOTAVAIL;
	case NLE_OBJ_NOTFOUND:		return ENOENT;
	case NLE_INTR:			return EINTR;
	case NLE_AGAIN:			return EAGAIN;
	case NLE_BAD_SOCK:		return ENOTSOCK;
	case NLE_NOACCESS:		return EACCES;
	case NLE_INVAL:			return EINVAL;
	case NLE_NOMEM:			return ENOMEM;
	case NLE_AF_NOSUPPORT:		return EAFNOSUPPORT;
	case NLE_PROTO_MISMATCH:	return EPROTONOSUPPORT;
	case NLE_OPNOTSUPP:		return EOPNOTSUPP;
	case NLE_PERM:			return EPERM;
	case NLE_BUSY:			return EBUSY;
	case NLE_RANGE:			return ERANGE;
	case NLE_NODEV:			return ENODEV;
	default:			return EINVAL;
	}
}

/**
 * SECTION: Netlink helpers
 * @short_description: Various netlink helpers
 */

static int ack_handler(struct nl_msg *msg, void *arg)
{
	bool *acked = arg;

	*acked = true;
	return NL_STOP;
}

static int seq_check_handler(struct nl_msg *msg, void *arg)
{
	unsigned int *seq = arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	if (hdr->nlmsg_seq != *seq)
		return NL_SKIP;
	return NL_OK;
}

int send_and_recv(struct team_handle *th, struct nl_msg *msg,
		  int (*valid_handler)(struct nl_msg *, void *),
		  void *valid_data)
{
	int ret;
	struct nl_cb *cb;
	struct nl_cb *orig_cb;
	bool acked;
	unsigned int seq = th->nl_sock_seq++;
	int err;

	ret = nl_send_auto(th->nl_sock, msg);
	nlmsg_free(msg);
	if (ret < 0)
		return -nl2syserr(ret);

	orig_cb = nl_socket_get_cb(th->nl_sock);
	cb = nl_cb_clone(orig_cb);
	nl_cb_put(orig_cb);
	if (!cb)
		return -ENOMEM;

	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &acked);
	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, seq_check_handler, &seq);
	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	/* There is a bug in libnl. When implicit sequence number checking is in
	 * use the expected next number is increased when NLMSG_DONE is
	 * received. The ACK which comes after that correctly includes the
	 * original sequence number. However libnl is checking that number
	 * against the incremented one and therefore ack handler is never called
	 * and nl_recvmsgs finished with an error. To resolve this, custom
	 * sequence number checking is used here.
	 */

	acked = false;
	while (!acked) {
		ret = nl_recvmsgs(th->nl_sock, cb);
		if (ret) {
			err = -nl2syserr(ret);
			goto put_cb;
		}
	}

	err = 0;
put_cb:
	nl_cb_put(cb);
	return err;
}

/**
 * SECTION: Change handlers
 * @short_description: event change handlers handling
 */

struct change_handler_item {
	struct list_item			list;
	const struct team_change_handler *	handler;
	void *					priv;
};

void set_call_change_handlers(struct team_handle *th,
			      team_change_type_mask_t set_type_mask)
{
	th->change_handler.pending_type_mask |= set_type_mask;
}

int check_call_change_handlers(struct team_handle *th,
			       team_change_type_mask_t call_type_mask)
{
	int err = 0;
	struct change_handler_item *handler_item;
	team_change_type_mask_t to_call_type_mask =
			th->change_handler.pending_type_mask & call_type_mask;

	list_for_each_node_entry(handler_item, &th->change_handler.list, list) {
		const struct team_change_handler *handler =
				handler_item->handler;
		team_change_type_mask_t item_type_mask =
				handler->type_mask & to_call_type_mask;

		if (item_type_mask) {
			err = handler->func(th, handler_item->priv,
					    item_type_mask);
			if (err)
				break;
		}
	}
	th->change_handler.pending_type_mask &= ~call_type_mask;
	return err;
}

static struct change_handler_item *
find_change_handler(struct team_handle *th,
		    const struct team_change_handler *handler,
		    void *priv)
{
	struct change_handler_item *handler_item;

	list_for_each_node_entry(handler_item, &th->change_handler.list, list)
		if (handler_item->handler == handler &&
		    handler_item->priv == priv)
			return handler_item;
	return NULL;
}

/**
 * team_change_handler_register:
 * @th: libteam library context
 * @handler: event handler structure
 * @priv: event handler func private data
 *
 * Registers custom @handler structure which defines a function which
 * going to be called on defined events.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_change_handler_register(struct team_handle *th,
				 const struct team_change_handler *handler,
				 void *priv)
{
	struct change_handler_item *handler_item;

	if (find_change_handler(th, handler, priv))
		return -EEXIST;
	handler_item = malloc(sizeof(struct change_handler_item));
	if (!handler_item)
		return -ENOMEM;
	handler_item->handler = handler;
	handler_item->priv = priv;
	list_add_tail(&th->change_handler.list, &handler_item->list);
	return 0;
}

/**
 * team_change_handler_unregister:
 * @th: libteam library context
 * @handler: event handler structure
 * @priv: event handler func private data
 *
 * Unregisters custom @handler structure.
 *
 **/
TEAM_EXPORT
void team_change_handler_unregister(struct team_handle *th,
				    const struct team_change_handler *handler,
				    void *priv)
{
	struct change_handler_item *handler_item;

	handler_item = find_change_handler(th, handler, priv);
	if (!handler_item)
		return;
	list_del(&handler_item->list);
	free(handler_item);
}

/**
 * SECTION: Context functions
 * @short_description: Core context functions
 */

static int event_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	switch (gnlh->cmd) {
	case TEAM_CMD_PORT_LIST_GET:
		return get_port_list_handler(msg, arg);
	case TEAM_CMD_OPTIONS_GET:
		return get_options_handler(msg, arg);
	}
	return NL_SKIP;
}

static int cli_event_handler(struct nl_msg *msg, void *arg)
{
	return ifinfo_event_handler(msg, arg);
}

static int team_init_event_fd(struct team_handle *th);

/**
 * team_alloc:
 *
 * Allocates library context, sockets, initializes rtnl netlink connection.
 *
 * Returns: new libteam library context
 **/
TEAM_EXPORT
struct team_handle *team_alloc(void)
{
	struct team_handle *th;
	const char *env;
	int err;

	th = myzalloc(sizeof(struct team_handle));
	if (!th)
		return NULL;

	th->log_fn = log_stderr;
	th->log_priority = LOG_ERR;
	/* environment overwrites config */
	env = getenv("TEAM_LOG");
	if (env != NULL)
		team_set_log_priority(th, log_priority(env));

	dbg(th, "team_handle %p created.", th);
	dbg(th, "log_priority=%d", th->log_priority);

	list_init(&th->change_handler.list);

	err = ifinfo_list_alloc(th);
	if (err)
		goto err_ifinfo_list_alloc;
	err = port_list_alloc(th);
	if (err)
		goto err_port_list_alloc;
	err = option_list_alloc(th);
	if (err)
		goto err_option_list_alloc;

	th->nl_sock = nl_socket_alloc();
	if (!th->nl_sock)
		goto err_sk_alloc;

	th->nl_sock_event = nl_socket_alloc();
	if (!th->nl_sock_event)
		goto err_sk_event_alloc;

	th->nl_cli.sock_event = nl_cli_alloc_socket();
	if (!th->nl_cli.sock_event)
		goto err_cli_sk_event_alloc;

	th->nl_cli.sock = nl_cli_alloc_socket();
	if (!th->nl_cli.sock)
		goto err_cli_sk_alloc;
	err = nl_cli_connect(th->nl_cli.sock, NETLINK_ROUTE);
	if (err)
		goto err_cli_connect;

	return th;

err_cli_connect:
	nl_socket_free(th->nl_cli.sock);

err_cli_sk_alloc:
	nl_socket_free(th->nl_cli.sock_event);

err_cli_sk_event_alloc:
	nl_socket_free(th->nl_sock_event);

err_sk_event_alloc:
	nl_socket_free(th->nl_sock);

err_sk_alloc:
	option_list_free(th);

err_option_list_alloc:
	port_list_free(th);

err_port_list_alloc:
	ifinfo_list_free(th);

err_ifinfo_list_alloc:
	free(th);

	return NULL;
}

static int do_create(struct team_handle *th, const char *team_name, bool recreate)
{
	struct rtnl_link *link;
	int err;

	link = rtnl_link_alloc();
	if (!link)
		return -ENOMEM;

	if (team_name) {
		rtnl_link_set_name(link, team_name);

		if (recreate && team_ifname2ifindex(th, team_name)) {
			err = rtnl_link_delete(th->nl_cli.sock, link);
			if (err)
				goto errout;
		}
	}

	err = rtnl_link_set_type(link, "team");
	if (err)
		goto errout;

	err = rtnl_link_add(th->nl_cli.sock, link, NLM_F_CREATE | NLM_F_EXCL);

errout:
	rtnl_link_put(link);

	return -nl2syserr(err);
}

/**
 * team_create:
 * @th: libteam library context
 * @team_name: new team device name
 *
 * Create new team device by given name. If NULL is passed, name will be
 * allocated automatically.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_create(struct team_handle *th, const char *team_name)
{
	return do_create(th, team_name, false);
}

/**
 * team_recreate:
 * @th: libteam library context
 * @team_name: new team device name
 *
 * Does the same as team_create only if device with @team_name already
 * exists it will be deleted first.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_recreate(struct team_handle *th, const char *team_name)
{
	return do_create(th, team_name, true);
}

/**
 * team_destroy:
 * @th: libteam library context
 *
 * Destroys current initialized team device.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_destroy(struct team_handle *th)
{
	struct rtnl_link *link;
	int err;

	if (!th->ifindex)
		return -ENODEV;
	link = rtnl_link_alloc();
	if (!link)
		return -ENOMEM;
	rtnl_link_set_ifindex(link, th->ifindex);
	err = rtnl_link_delete(th->nl_cli.sock, link);
	rtnl_link_put(link);
	return -nl2syserr(err);
}

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef NETLINK_BROADCAST_SEND_ERROR
#define NETLINK_BROADCAST_SEND_ERROR    0x4
#endif

/**
 * team_init:
 * @th: libteam library context
 * @ifindex: team device interface index
 *
 * Do library context initialization. Sets up team generic netlink connection.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_init(struct team_handle *th, uint32_t ifindex)
{
	int err;
	int grp_id;
	int val;

	if (!ifindex) {
		err(th, "Passed interface index %d is not valid.", ifindex);
		return -EINVAL;
	}
	th->ifindex = ifindex;

	th->nl_sock_seq = time(NULL);
	err = genl_connect(th->nl_sock);
	if (err) {
		err(th, "Failed to connect to netlink sock.");
		return -nl2syserr(err);
	}

	err = genl_connect(th->nl_sock_event);
	if (err) {
		err(th, "Failed to connect to netlink event sock.");
		return -nl2syserr(err);
	}

	val = NETLINK_BROADCAST_SEND_ERROR;
	err = setsockopt(nl_socket_get_fd(th->nl_sock_event), SOL_NETLINK,
			 NETLINK_BROADCAST_ERROR, &val, sizeof(val));
	if (err) {
		err(th, "Failed set NETLINK_BROADCAST_ERROR on netlink event sock.");
		return -errno;
	}

	err = nl_socket_set_buffer_size(th->nl_sock, 98304, 0);
	if (err) {
		err(th, "Failed to set buffer size of netlink sock.");
		return -nl2syserr(err);
	}
	err = nl_socket_set_buffer_size(th->nl_sock_event, 98304, 0);
	if (err) {
		err(th, "Failed to set buffer size of netlink event sock.");
		return -nl2syserr(err);
	}

	th->family = genl_ctrl_resolve(th->nl_sock, TEAM_GENL_NAME);
	if (th->family < 0) {
		err(th, "Failed to resolve netlink family.");
		return -nl2syserr(th->family);
	}

	grp_id = genl_ctrl_resolve_grp(th->nl_sock, TEAM_GENL_NAME,
				       TEAM_GENL_CHANGE_EVENT_MC_GRP_NAME);
	if (grp_id < 0) {
		err(th, "Failed to resolve netlink multicast groups.");
		return -nl2syserr(grp_id);
	}

	err = nl_socket_add_membership(th->nl_sock_event, grp_id);
	if (err < 0) {
		err(th, "Failed to add netlink membership.");
		return -nl2syserr(err);
	}

	nl_socket_disable_seq_check(th->nl_sock_event);
	nl_socket_modify_cb(th->nl_sock_event, NL_CB_VALID, NL_CB_CUSTOM,
			    event_handler, th);

	nl_socket_disable_seq_check(th->nl_cli.sock_event);
	nl_socket_modify_cb(th->nl_cli.sock_event, NL_CB_VALID,
			    NL_CB_CUSTOM, cli_event_handler, th);
	nl_cli_connect(th->nl_cli.sock_event, NETLINK_ROUTE);
	err = nl_socket_add_membership(th->nl_cli.sock_event, RTNLGRP_LINK);
	if (err < 0) {
		err(th, "Failed to add netlink membership.");
		return -nl2syserr(err);
	}

	err = ifinfo_list_init(th);
	if (err) {
		err(th, "Failed to init interface information list.");
		return err;
	}

	err = port_list_init(th);
	if (err) {
		err(th, "Failed to init port list.");
		return err;
	}

	err = option_list_init(th);
	if (err) {
		err(th, "Failed to init option list.");
		return err;
	}

	err = ifinfo_link(th, ifindex, &th->ifinfo);
	if (err) {
		err(th, "Failed to find team interface info.");
		return err;
	}

	err = team_init_event_fd(th);
	if (err) {
		err(th, "Failed to init event fd.");
		return err;
	}

	return 0;
}

/**
 * team_free:
 * @th: libteam library context
 *
 * Do library context cleanup.
 *
 **/
TEAM_EXPORT
void team_free(struct team_handle *th)
{
	close(th->event_fd);
	ifinfo_list_free(th);
	port_list_free(th);
	option_list_free(th);
	nl_socket_free(th->nl_cli.sock);
	nl_socket_free(th->nl_cli.sock_event);
	nl_socket_free(th->nl_sock_event);
	nl_socket_free(th->nl_sock);
	free(th);
}

/**
 * team_set_log_fn:
 * @th: libteam library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging writes to stderr. It can be
 * overridden by a custom function, to plug log messages
 * into the user's logging functionality.
 *
 **/
TEAM_EXPORT
void team_set_log_fn(struct team_handle *th,
		     void (*log_fn)(struct team_handle *th, int priority,
				    const char *file, int line, const char *fn,
				    const char *format, va_list args))
{
	th->log_fn = log_fn;
	dbg(th, "Custom logging function %p registered.", log_fn);
}

/**
 * team_get_log_priority:
 * @th: libteam library context
 *
 * Returns: the current logging priority
 **/
TEAM_EXPORT
int team_get_log_priority(struct team_handle *th)
{
	return th->log_priority;
}

/**
 * team_set_log_priority:
 * @th: libteam library context
 * @priority: the new logging priority
 *
 * Set the current logging priority. The value controls which messages
 * are logged.
 **/
TEAM_EXPORT
void team_set_log_priority(struct team_handle *th, int priority)
{
	th->log_priority = priority;
}

static int get_cli_sock_event_fd(struct team_handle *th)
{
	return nl_socket_get_fd(th->nl_cli.sock_event);
}

static int cli_sock_event_handler(struct team_handle *th)
{
	nl_recvmsgs_default(th->nl_cli.sock_event);
	return check_call_change_handlers(th, TEAM_IFINFO_CHANGE);
}

static int get_sock_event_fd(struct team_handle *th)
{
	return nl_socket_get_fd(th->nl_sock_event);
}

static int sock_event_handler(struct team_handle *th)
{
	int ret;

	ret = nl_recvmsgs_default(th->nl_sock_event);
	if (ret)
		return -nl2syserr(ret);

	th->msg_recv_started = false;
	return check_call_change_handlers(th, TEAM_PORT_CHANGE |
					      TEAM_OPTION_CHANGE |
					      TEAM_IFINFO_CHANGE);
}

struct team_eventfd {
	int (*get_fd)(struct team_handle *th);
	int (*event_handler)(struct team_handle *th);
};

static const struct team_eventfd team_eventfds[] = {
	/* Always handle cli socket first. The reason is that cli socket
	 * message may include information, like master unset, which may be
	 * handy to have before proceeding others.
	 */
	{
		.get_fd = get_cli_sock_event_fd,
		.event_handler = cli_sock_event_handler,
	},
	{
		.get_fd = get_sock_event_fd,
		.event_handler = sock_event_handler,
	},
};
#define TEAM_EVENT_FDS_COUNT ARRAY_SIZE(team_eventfds)

static const struct team_eventfd __dummy_eventfd;

/**
 * team_get_next_eventfd:
 * @th: libteam library context
 * @eventfd: eventfd structure
 *
 * Get next eventfd in list.
 *
 * Returns: eventfd next to @eventfd passed.
 *
 * @deprecated Use of this function is deprecated.
 **/
TEAM_EXPORT
const struct team_eventfd *team_get_next_eventfd(struct team_handle *th,
						 const struct team_eventfd *eventfd)
{
	if (!eventfd)
		return &__dummy_eventfd;
	return NULL;
}

/**
 * team_get_eventfd_fd:
 * @th: libteam library context
 * @eventfd: eventfd structure
 *
 * Get eventfd filedesctiptor.
 *
 * Returns: fd.
 *
 * @deprecated Use of this function is deprecated. User should use
 *	       team_get_event_fd() funstion instead.
 **/
TEAM_EXPORT
int team_get_eventfd_fd(struct team_handle *th,
			const struct team_eventfd *eventfd)
{
	return team_get_event_fd(th);
}

/**
 * team_call_eventfd_handler:
 * @th: libteam library context
 * @eventfd: eventfd structure
 *
 * Call eventfd handler.
 *
 * Returns: zero on success or negative number in case of an error.
 *
 * @deprecated Use of this function is deprecated. User should use
 *	       team_handle_events() funstion instead.
 **/
TEAM_EXPORT
int team_call_eventfd_handler(struct team_handle *th,
			      const struct team_eventfd *eventfd)
{
	return team_handle_events(th);
}

static int team_init_event_fd(struct team_handle *th)
{
	int efd;
	int i;
	struct epoll_event event;
	int err;

	efd = epoll_create1(0);
	if (efd == -1)
		return -errno;
	for (i = 0; i < TEAM_EVENT_FDS_COUNT; i++) {
		int fd = team_eventfds[i].get_fd(th);

		event.data.fd = fd;
		event.events = EPOLLIN;
		err = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
		if (err == -1) {
			err = -errno;
			goto close_efd;
		}
	}
	th->event_fd = efd;
	return 0;

close_efd:
	close(efd);
	return err;
}

/**
 * team_get_event_fd:
 * @th: libteam library context
 *
 * Get event filedesctiptor.
 *
 * Returns: fd.
 **/
TEAM_EXPORT
int team_get_event_fd(struct team_handle *th)
{
	return th->event_fd;
}

/**
 * team_handle_events:
 * @th: libteam library context
 * @eventfd: eventfd structure
 *
 * Handler events which happened on event filedescriptor.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_handle_events(struct team_handle *th)
{
	struct epoll_event events[TEAM_EVENT_FDS_COUNT];
	int nfds;
	int n;
	int i;
	int err;

	nfds = epoll_wait(th->event_fd, events, TEAM_EVENT_FDS_COUNT, -1);
	if (nfds == -1)
		return -errno;

	/* Go over list of event fds and handle them sequentially */
	for (i = 0; i < TEAM_EVENT_FDS_COUNT; i++) {
		const struct team_eventfd *eventfd = &team_eventfds[i];

		for (n = 0; n < nfds; n++) {
			if (events[n].data.fd == eventfd->get_fd(th)) {
				err = eventfd->event_handler(th);
				if (err)
					return err;
			}
		}
	}
	return 0;
}

/**
 * team_check_events:
 * @th: libteam library context
 *
 * Check for events pending to be processed on event socket and process
 * them one by one. This is safe to be called even if no data present
 * on event socket file descriptor.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_check_events(struct team_handle *th)
{
	fd_set rfds;
	int fdmax;
	struct timeval tv;
	int fd = team_get_event_fd(th);
	int ret;

	memset(&tv, 0, sizeof(tv));
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	fdmax = fd + 1;
	ret = select(fdmax, &rfds, NULL, NULL, &tv);
	if (ret == -1)
		return -errno;
	return team_handle_events(th);
}

/**
 * team_get_mode_name:
 * @th: libteam library context
 * @mode_name: where the mode name will be stored
 *
 * Get name of currect mode.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_mode_name(struct team_handle *th, char **mode_name)
{
	struct team_option *option;

	option = team_get_option(th, "n", "mode");
	if (!option)
		return -ENOENT;
	*mode_name = team_get_option_value_string(option);
	return 0;
}

/**
 * team_set_mode_name:
 * @th: libteam library context
 * @mode_name: name of mode to be set
 *
 * Set team mode.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_mode_name(struct team_handle *th, const char *mode_name)
{
	struct team_option *option;

	option = team_get_option(th, "n!", "mode");
	if (!option)
		return -ENOENT;
	return team_set_option_value_string(th, option, mode_name);
}

/**
 * team_get_notify_peers_count:
 * @th: libteam library context
 * @count: where the count will be stored
 *
 * Get number of bursts of NAs and ARPs notifications sent to peers.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_notify_peers_count(struct team_handle *th, uint32_t *count)
{
	struct team_option *option;

	option = team_get_option(th, "n", "notify_peers_count");
	if (!option)
		return -ENOENT;
	*count = team_get_option_value_u32(option);
	return 0;
}

/**
 * team_set_notify_peers_count:
 * @th: libteam library context
 * @count: number of bursts
 *
 * Set number of bursts of NAs and ARPs notifications sent to peers.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_notify_peers_count(struct team_handle *th, uint32_t count)
{
	struct team_option *option;

	option = team_get_option(th, "n!", "notify_peers_count");
	if (!option)
		return -ENOENT;
	return team_set_option_value_u32(th, option, count);
}

/**
 * team_get_notify_peers_interval:
 * @th: libteam library context
 * @interval: where the interval will be stored
 *
 * Get interval (in milliseconds) in which bursts of NAs and ARPs notifications
 * are sent to peers.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_notify_peers_interval(struct team_handle *th, uint32_t *interval)
{
	struct team_option *option;

	option = team_get_option(th, "n", "notify_peers_interval");
	if (!option)
		return -ENOENT;
	*interval = team_get_option_value_u32(option);
	return 0;
}

/**
 * team_set_notify_peers_interval:
 * @th: libteam library context
 * @interval: interval of bursts
 *
 * Set interval (in milliseconds) in which bursts of NAs and ARPs notifications
 * will be sent to peers.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_notify_peers_interval(struct team_handle *th, uint32_t interval)
{
	struct team_option *option;

	option = team_get_option(th, "n!", "notify_peers_interval");
	if (!option)
		return -ENOENT;
	return team_set_option_value_u32(th, option, interval);
}

/**
 * team_get_mcast_rejoin_count:
 * @th: libteam library context
 * @count: where the count will be stored
 *
 * Get number of bursts of multicast group rejoins to be sent.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_mcast_rejoin_count(struct team_handle *th, uint32_t *count)
{
	struct team_option *option;

	option = team_get_option(th, "n", "mcast_rejoin_count");
	if (!option)
		return -ENOENT;
	*count = team_get_option_value_u32(option);
	return 0;
}

/**
 * team_set_mcast_rejoin_count:
 * @th: libteam library context
 * @count: number of bursts
 *
 * Set number of bursts of multicast group rejoins to be sent.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_mcast_rejoin_count(struct team_handle *th, uint32_t count)
{
	struct team_option *option;

	option = team_get_option(th, "n!", "mcast_rejoin_count");
	if (!option)
		return -ENOENT;
	return team_set_option_value_u32(th, option, count);
}

/**
 * team_get_mcast_rejoin_interval:
 * @th: libteam library context
 * @interval: where the interval will be stored
 *
 * Get interval (in milliseconds) in which bursts of rejoins are sent.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_mcast_rejoin_interval(struct team_handle *th, uint32_t *interval)
{
	struct team_option *option;

	option = team_get_option(th, "n", "mcast_rejoin_interval");
	if (!option)
		return -ENOENT;
	*interval = team_get_option_value_u32(option);
	return 0;
}

/**
 * team_set_mcast_rejoin_interval:
 * @th: libteam library context
 * @interval: interval of bursts
 *
 * Set interval (in milliseconds) in which bursts of rejoins are sent.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_mcast_rejoin_interval(struct team_handle *th, uint32_t interval)
{
	struct team_option *option;

	option = team_get_option(th, "n!", "mcast_rejoin_interval");
	if (!option)
		return -ENOENT;
	return team_set_option_value_u32(th, option, interval);
}

/**
 * team_get_active_port:
 * @th: libteam library context
 * @ifindex: where the port interface index will be stored
 *
 * Get interface index of active port. Note this is possible only if
 * team is in "activebackup" mode.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_active_port(struct team_handle *th, uint32_t *ifindex)
{
	struct team_option *option;

	option = team_get_option(th, "n", "activeport");
	if (!option)
		return -ENOENT;
	*ifindex = team_get_option_value_u32(option);
	return 0;
}

/**
 * team_set_active_port:
 * @th: libteam library context
 * @ifindex: interface index of new active port
 *
 * Set new active port by give @ifindex. Note this is possible only if
 * team is in "activebackup" mode.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_active_port(struct team_handle *th, uint32_t ifindex)
{
	struct team_option *option;

	option = team_get_option(th, "n!", "activeport");
	if (!option)
		return -ENOENT;
	return team_set_option_value_u32(th, option, ifindex);
}

/**
 * team_get_bpf_hash_func:
 * @th: libteam library context
 * @fp: where current BPF instruction set will be stored
 *
 * Get tx port selecting hash function. Note this is possible only if
 * team is in "loadbalance" mode.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_bpf_hash_func(struct team_handle *th, struct sock_fprog *fp)
{
	struct team_option *option;
	unsigned int data_len;

	option = team_get_option(th, "n", "bpf_hash_func");
	if (!option)
		return -ENOENT;

	data_len = team_get_option_value_len(option);
	if (data_len % sizeof(struct sock_filter))
		return -EINVAL;

	fp->filter = team_get_option_value_binary(option);
	fp->len = data_len / sizeof(struct sock_filter);
	return 0;
}

/**
 * team_set_bpf_hash_func:
 * @th: libteam library context
 * @fp: prepared BPF instruction set
 *
 * Set tx port selecting hash function. Note this is possible only if
 * team is in "loadbalance" mode. Passing NULL clears current function.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_bpf_hash_func(struct team_handle *th, const struct sock_fprog *fp)
{
	void *data = NULL;
	unsigned int data_len = 0;
	struct team_option *option;

	option = team_get_option(th, "n!", "bpf_hash_func");
	if (!option)
		return -ENOENT;

	if (fp) {
		data = fp->filter;
		data_len = fp->len * sizeof(struct sock_filter);
	}
	return team_set_option_value_binary(th, option, data, data_len);
}

/**
 * team_set_port_enabled:
 * @th: libteam library context
 * @port_ifindex: port interface index
 * @val: boolean value
 *
 * Enables or disable port identified by @port_ifindex
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_port_enabled(struct team_handle *th,
			  uint32_t port_ifindex, bool val)
{
	struct team_option *option;

	option = team_get_option(th, "np!", "enabled", port_ifindex);
	if (!option)
		return -ENOENT;
	return team_set_option_value_bool(th, option, val);
}

/**
 * team_set_port_user_linkup_enabled:
 * @th: libteam library context
 * @port_ifindex: port interface index
 * @val: boolean value
 *
 * Enables or disable user linkup for port identified by @port_ifindex
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_port_user_linkup_enabled(struct team_handle *th,
				      uint32_t port_ifindex, bool val)
{
	struct team_option *option;

	option = team_get_option(th, "np!", "user_linkup_enabled",
				 port_ifindex);
	if (!option)
		return -ENOENT;
	return team_set_option_value_bool(th, option, val);
}

/**
 * team_get_port_user_linkup:
 * @th: libteam library context
 * @port_ifindex: port interface index
 * @ifindex: where the port user link state will be stored
 *
 * Gets user linkup for port identified by @port_ifindex
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_port_user_linkup(struct team_handle *th,
			      uint32_t port_ifindex, bool *linkup)
{
	struct team_option *option;

	option = team_get_option(th, "np", "user_linkup", port_ifindex);
	if (!option)
		return -ENOENT;
	*linkup = team_get_option_value_bool(option);
	return 0;
}

/**
 * team_set_port_user_linkup:
 * @th: libteam library context
 * @port_ifindex: port interface index
 * @linkup: desired link state
 *
 * Sets user linkup for port identified by @port_ifindex
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_port_user_linkup(struct team_handle *th,
			      uint32_t port_ifindex, bool linkup)
{
	struct team_option *option;

	option = team_get_option(th, "np!", "user_linkup", port_ifindex);
	if (!option)
		return -ENOENT;

	return team_set_option_value_bool(th, option, linkup);
}

/**
 * team_set_port_queue_id:
 * @th: libteam library context
 * @port_ifindex: port interface index
 * @queue_id: desired queue id
 *
 * Sets queue id for port identified by @port_ifindex
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_port_queue_id(struct team_handle *th,
			   uint32_t port_ifindex, uint32_t queue_id)
{
	struct team_option *option;

	option = team_get_option(th, "np!", "queue_id", port_ifindex);
	if (!option)
		return -ENOENT;

	return team_set_option_value_u32(th, option, queue_id);
}

/**
 * team_get_port_priority:
 * @th: libteam library context
 * @port_ifindex: port interface index
 * @priority: where the port priority will be stored
 *
 * Gets priority for port identified by @port_ifindex
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_port_priority(struct team_handle *th,
			   uint32_t port_ifindex, int32_t *priority)
{
	struct team_option *option;

	option = team_get_option(th, "np", "priority", port_ifindex);
	if (!option)
		return -ENOENT;
	*priority = team_get_option_value_s32(option);
	return 0;
}

/**
 * team_set_port_priority:
 * @th: libteam library context
 * @port_ifindex: port interface index
 * @priority: desired priority
 *
 * Sets priority for port identified by @port_ifindex
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_port_priority(struct team_handle *th,
			   uint32_t port_ifindex, int32_t priority)
{
	struct team_option *option;

	option = team_get_option(th, "np!", "priority", port_ifindex);
	if (!option)
		return -ENOENT;

	return team_set_option_value_s32(th, option, priority);
}

/**
 * SECTION: RTNL helpers
 * @short_description: Route netlink helper function
 */

/**
 * team_ifname2ifindex:
 * @th: libteam library context
 * @ifname: interface name
 *
 * Looks up for interface of given name and gets its index.
 *
 * Returns: zero if interface is not found,
 *	    interface index as reffered by in kernel otherwise.
 **/
TEAM_EXPORT
uint32_t team_ifname2ifindex(struct team_handle *th, const char *ifname)
{
	struct rtnl_link *link;
	uint32_t ifindex;
	int err;

	err = rtnl_link_get_kernel(th->nl_cli.sock, 0, ifname, &link);
	if (err)
		return 0;
	ifindex = rtnl_link_get_ifindex(link);
	rtnl_link_put(link);
	return ifindex;
}

/**
 * team_ifindex2ifname:
 * @th: libteam library context
 * @ifindex: interface index
 * @ifname: where the interface name will be stored
 * @maxlen: length of ifname buffer
 *
 * Looks up for interface of given index and gets its name.
 *
 * Returns: NULL if interface is not found,
 *	    @ifname otherwise.
 **/
TEAM_EXPORT
char *team_ifindex2ifname(struct team_handle *th, uint32_t ifindex,
			  char *ifname, unsigned int maxlen)
{
	struct rtnl_link *link;
	int err;

	err = rtnl_link_get_kernel(th->nl_cli.sock, ifindex, NULL, &link);
	if (err)
		return NULL;
	mystrlcpy(ifname, rtnl_link_get_name(link), maxlen);
	rtnl_link_put(link);
	return ifname;
}

/**
 * team_port_add:
 * @th: libteam library context
 * @port_ifindex: port interface index
 *
 * Adds port into team.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_port_add(struct team_handle *th, uint32_t port_ifindex)
{
	int err;

	err = rtnl_link_enslave_ifindex(th->nl_cli.sock, th->ifindex,
					port_ifindex);
	return -nl2syserr(err);
}

/**
 * team_our_port_port:
 * @th: libteam library context
 * @port_ifindex: port interface index
 *
 * Find out if interface is port of this team.
 *
 * Returns: true if interface is port of this team.
 **/
TEAM_EXPORT
bool team_is_our_port(struct team_handle *th, uint32_t port_ifindex)
{
	struct rtnl_link *link;
	int err;
	bool ret;

	err = rtnl_link_get_kernel(th->nl_cli.sock, port_ifindex, NULL, &link);
	if (err)
		return false;
	ret = rtnl_link_get_master(link) == th->ifindex;
	rtnl_link_put(link);
	return ret;
}

/**
 * team_port_remove:
 * @th: libteam library context
 * @port_ifindex: port interface index
 *
 * Removes port from team.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_port_remove(struct team_handle *th, uint32_t port_ifindex)
{
	int err;

	err = rtnl_link_release_ifindex(th->nl_cli.sock, port_ifindex);
	return -nl2syserr(err);
}

/**
 * team_carrier_set:
 * @th: libteam library context
 * @ifindex: interface index
 * @status: carrier status
 *
 * Sets carrier status for the master network interface
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_carrier_set(struct team_handle *th, bool carrier_up)
{
#ifdef HAVE_RTNL_LINK_SET_CARRIER
	struct rtnl_link *link;
	int err;

	link = rtnl_link_alloc();
	if (!link)
		return -ENOMEM;

	rtnl_link_set_ifindex(link, th->ifindex);
	rtnl_link_set_carrier(link, carrier_up ? 1 : 0);

	err = rtnl_link_change(th->nl_cli.sock, link, link, 0);
	err = -nl2syserr(err);

	rtnl_link_put(link);
	if (err == -EINVAL) {
		warn(th, "Failed to set carrier. Kernel probably does not support setting carrier");
		return 0;
	}
	return err;
#else
	return -EOPNOTSUPP;
#endif
}

/**
 * team_carrier_get:
 * @th: libteam library context
 * @carrier_up: where the carrier state will be stored
 *
 * Gets carrier status of the master network interface
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_carrier_get(struct team_handle *th, bool *carrier_up)
{
#ifdef HAVE_RTNL_LINK_GET_CARRIER
	struct rtnl_link *link;
	int carrier;
	int err;

	err = rtnl_link_get_kernel(th->nl_cli.sock, th->ifindex, NULL, &link);
	if (err)
		return -nl2syserr(err);

	carrier = rtnl_link_get_carrier(link);

	rtnl_link_put(link);
	*carrier_up = carrier ? true : false;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

/**
 * team_hwaddr_set:
 * @th: libteam library context
 * @ifindex: interface index
 * @addr: address to be set
 * @addr_len: length of addr
 *
 * Sets given hardware address (MAC) for network interface by given
 * interface index.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_hwaddr_set(struct team_handle *th, uint32_t ifindex,
		    const char *addr, unsigned int addr_len)
{
	struct rtnl_link *link;
	int err;
	struct nl_addr *nl_addr;

	link = rtnl_link_alloc();
	if (!link)
		return -ENOMEM;

	nl_addr = nl_addr_build(AF_UNSPEC, (void *) addr, addr_len);
	if (!nl_addr) {
		err = -ENOMEM;
		goto errout;
	}

	rtnl_link_set_ifindex(link, ifindex);
	rtnl_link_set_addr(link, nl_addr);

	err = rtnl_link_change(th->nl_cli.sock, link, link, 0);
	err = -nl2syserr(err);

	nl_addr_put(nl_addr);

errout:
	rtnl_link_put(link);
	return err;
}

/**
 * team_hwaddr_get:
 * @th: libteam library context
 * @ifindex: interface index
 * @addr: address will be written here
 * @addr_len: length of addr buffer
 *
 * Gets hardware address (MAC) of network interface by given
 * interface index.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_hwaddr_get(struct team_handle *th, uint32_t ifindex,
		    char *addr, unsigned int addr_len)
{
	struct rtnl_link *link;
	int err;
	struct nl_addr *nl_addr;

	err = rtnl_link_get_kernel(th->nl_cli.sock, ifindex, NULL, &link);
	if (err)
		return -nl2syserr(err);
	nl_addr = rtnl_link_get_addr(link);
	if (!nl_addr) {
		err = -ENOENT;
		goto errout;
	}

	if (nl_addr_get_len(nl_addr) != addr_len) {
		err = -EINVAL;
		goto errout;
	}

	memcpy(addr, nl_addr_get_binary_addr(nl_addr), addr_len);

errout:
	rtnl_link_put(link);
	return err;
}

/**
 * team_hwaddr_len_get:
 * @th: libteam library context
 * @ifindex: interface index
 *
 * Gets length of hardware address (MAC) of network interface by given
 * interface index.
 *
 * Returns: number of bytes on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_hwaddr_len_get(struct team_handle *th, uint32_t ifindex)
{
	struct rtnl_link *link;
	int err;
	struct nl_addr *nl_addr;

	err = rtnl_link_get_kernel(th->nl_cli.sock, ifindex, NULL, &link);
	if (err)
		return -nl2syserr(err);
	nl_addr = rtnl_link_get_addr(link);
	if (!nl_addr) {
		err = -ENOENT;
		goto errout;
	}

	err = nl_addr_get_len(nl_addr);

errout:
	rtnl_link_put(link);
	return err;
}

/**
 * team_get_ifinfo:
 * @th: libteam library context
 *
 * Get team device rtnetlink interface info.
 *
 * Returns: pointer to appropriate team_ifinfo structure.
 **/
TEAM_EXPORT
struct team_ifinfo *team_get_ifinfo(struct team_handle *th)
{
	return th->ifinfo;
}
