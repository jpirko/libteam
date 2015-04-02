/*
 *   teamd_lw_psr.c - Team port periodic send/receive link watcher
 *   Copyright (C) 2012-2015 Jiri Pirko <jiri@resnulli.us>
 *   Copyright (C) 2014 Erik Hugne <erik.hugne@ericsson.com>
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

#include <private/misc.h>
#include "teamd.h"
#include "teamd_link_watch.h"
#include "teamd_config.h"

/*
 * Generic periodic send/receive link watch "template"
 */

static const struct timespec lw_psr_default_init_wait = { 0, 1 };
#define LW_PSR_DEFAULT_MISSED_MAX 3

#define LW_PERIODIC_CB_NAME "lw_periodic"
static int lw_psr_callback_periodic(struct teamd_context *ctx, int events, void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = priv;
	struct teamd_port *tdport = common_ppriv->tdport;
	bool link_up = common_ppriv->link_up;
	int err;

	if (psr_ppriv->reply_received) {
		link_up = true;
		psr_ppriv->missed = 0;
	} else {
		psr_ppriv->missed++;
		if (psr_ppriv->missed > psr_ppriv->missed_max && link_up) {
			teamd_log_dbg("%s: Missed %u replies (max %u).",
				      tdport->ifname, psr_ppriv->missed,
				      psr_ppriv->missed_max);
			link_up = false;
		}
	}
	err = teamd_link_watch_check_link_up(ctx, tdport,
					     common_ppriv, link_up);
	if (err)
		return err;
	psr_ppriv->reply_received = false;

	return psr_ppriv->ops->send(psr_ppriv);
}

#define LW_SOCKET_CB_NAME "lw_socket"
static int lw_psr_callback_socket(struct teamd_context *ctx, int events, void *priv)
{
	struct lw_psr_port_priv *psr_ppriv = priv;

	return psr_ppriv->ops->receive(psr_ppriv);
}

static int lw_psr_load_options(struct teamd_context *ctx,
			       struct teamd_port *tdport,
			       struct lw_psr_port_priv *psr_ppriv)
{
	struct teamd_config_path_cookie *cpcookie = psr_ppriv->common.cpcookie;
	int err;
	int tmp;

	err = teamd_config_int_get(ctx, &tmp, "@.interval", cpcookie);
	if (err) {
		teamd_log_err("Failed to get \"interval\" link-watch option.");
		return -EINVAL;
	}
	teamd_log_dbg("interval \"%d\".", tmp);
	ms_to_timespec(&psr_ppriv->interval, tmp);

	err = teamd_config_int_get(ctx, &tmp, "@.init_wait", cpcookie);
	if (!err)
		ms_to_timespec(&psr_ppriv->init_wait, tmp);
	/* if init_wait is set to 0, use default_init_wait */
	if (err || !tmp)
		psr_ppriv->init_wait = lw_psr_default_init_wait;
	teamd_log_dbg("init_wait \"%d\".", timespec_to_ms(&psr_ppriv->init_wait));

	err = teamd_config_int_get(ctx, &tmp, "@.missed_max", cpcookie);
	if (!err) {
		if (tmp < 0) {
			teamd_log_err("\"missed_max\" must not be negative number.");
			return -EINVAL;
		}
	} else {
		tmp = LW_PSR_DEFAULT_MISSED_MAX;
	}
	teamd_log_dbg("missed_max \"%d\".", tmp);
	psr_ppriv->missed_max = tmp;

	return 0;
}

struct lw_psr_port_priv *
lw_psr_ppriv_get(struct lw_common_port_priv *common_ppriv)
{
	return (struct lw_psr_port_priv *) common_ppriv;
}


int lw_psr_port_added(struct teamd_context *ctx, struct teamd_port *tdport,
		      void *priv, void *creator_priv)
{
	struct lw_psr_port_priv *psr_ppriv = priv;
	int err;

	err = lw_psr_load_options(ctx, tdport, psr_ppriv);
	if (err) {
		teamd_log_err("Failed to load options.");
		return err;
	}

	err = psr_ppriv->ops->load_options(ctx, tdport, psr_ppriv);
	if (err) {
		teamd_log_err("Failed to load options.");
		return err;
	}

	err = psr_ppriv->ops->sock_open(psr_ppriv);
	if (err) {
		teamd_log_err("Failed to create socket.");
		return err;
	}

	err = teamd_loop_callback_fd_add(ctx, LW_SOCKET_CB_NAME, psr_ppriv,
					 lw_psr_callback_socket,
					 psr_ppriv->sock,
					 TEAMD_LOOP_FD_EVENT_READ);
	if (err) {
		teamd_log_err("Failed add socket callback.");
		goto close_sock;
	}

	err = teamd_loop_callback_timer_add_set(ctx, LW_PERIODIC_CB_NAME,
						psr_ppriv,
						lw_psr_callback_periodic,
						&psr_ppriv->interval,
						&psr_ppriv->init_wait);
	if (err) {
		teamd_log_err("Failed add callback timer");
		goto socket_callback_del;
	}

	err = team_set_port_user_linkup_enabled(ctx->th, tdport->ifindex, true);
	if (err) {
		teamd_log_err("%s: Failed to enable user linkup.",
			      tdport->ifname);
		goto periodic_callback_del;
	}

	teamd_loop_callback_enable(ctx, LW_SOCKET_CB_NAME, psr_ppriv);
	teamd_loop_callback_enable(ctx, LW_PERIODIC_CB_NAME, psr_ppriv);
	return 0;

periodic_callback_del:
	teamd_loop_callback_del(ctx, LW_PERIODIC_CB_NAME, psr_ppriv);
socket_callback_del:
	teamd_loop_callback_del(ctx, LW_SOCKET_CB_NAME, psr_ppriv);
close_sock:
	psr_ppriv->ops->sock_close(psr_ppriv);
	return err;
}

void lw_psr_port_removed(struct teamd_context *ctx, struct teamd_port *tdport,
			 void *priv, void *creator_priv)
{
	struct lw_psr_port_priv *psr_ppriv = priv;

	teamd_loop_callback_del(ctx, LW_PERIODIC_CB_NAME, psr_ppriv);
	teamd_loop_callback_del(ctx, LW_SOCKET_CB_NAME, psr_ppriv);
	psr_ppriv->ops->sock_close(psr_ppriv);
}

int lw_psr_state_interval_get(struct teamd_context *ctx,
			      struct team_state_gsc *gsc,
			      void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);

	gsc->data.int_val = timespec_to_ms(&psr_ppriv->interval);
	return 0;
}

int lw_psr_state_init_wait_get(struct teamd_context *ctx,
			       struct team_state_gsc *gsc,
			       void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);

	gsc->data.int_val = timespec_to_ms(&psr_ppriv->init_wait);
	return 0;
}

int lw_psr_state_missed_max_get(struct teamd_context *ctx,
				struct team_state_gsc *gsc,
				void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);

	gsc->data.int_val = psr_ppriv->missed_max;
	return 0;
}

int lw_psr_state_missed_get(struct teamd_context *ctx,
			    struct team_state_gsc *gsc,
			    void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);

	gsc->data.int_val = psr_ppriv->missed;
	return 0;
}
