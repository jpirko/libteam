/*
 *   teamd_lw_ethtool.c - Team port ethtool link watcher
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
 * Ethtool link watch
 */

struct lw_ethtool_port_priv {
	struct lw_common_port_priv common; /* must be first */
	struct timespec delay_up;
	struct timespec delay_down;
};

static struct lw_ethtool_port_priv *
lw_ethtool_ppriv_get(struct lw_common_port_priv *common_ppriv)
{
	return (struct lw_ethtool_port_priv *) common_ppriv;
}

#define LW_ETHTOOL_DELAY_CB_NAME "lw_ethtool_delay"

static int lw_ethtool_event_watch_port_changed(struct teamd_context *ctx,
					       struct teamd_port *tdport,
					       void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_ethtool_port_priv *ethtool_ppriv = priv;
	bool link_up;
	struct timespec *delay;
	int err;

	if (common_ppriv->tdport != tdport ||
	    !team_is_port_changed(tdport->team_port))
		return 0;

	/*
	 * Link changed for sure, so if there is some delay in progress,
	 * cancel it before proceeding.
	 */
	teamd_loop_callback_disable(ctx, LW_ETHTOOL_DELAY_CB_NAME, priv);
	link_up = team_is_port_link_up(tdport->team_port);
	if (!teamd_link_watch_link_up_differs(common_ppriv, link_up))
		return 0;

	if (link_up) {
		if (timespec_is_zero(&ethtool_ppriv->delay_up))
			goto nodelay;
		delay = &ethtool_ppriv->delay_up;
	} else {
		if (timespec_is_zero(&ethtool_ppriv->delay_down))
			goto nodelay;
		delay = &ethtool_ppriv->delay_down;
	}

	err = teamd_loop_callback_timer_set(ctx, LW_ETHTOOL_DELAY_CB_NAME,
					    priv, NULL, delay);
	if (err) {
		teamd_log_err("Failed to set delay timer.");
		return err;
	}
	teamd_loop_callback_enable(ctx, LW_ETHTOOL_DELAY_CB_NAME, priv);
	return 0;

nodelay:
	return teamd_link_watch_check_link_up(ctx, tdport, common_ppriv,
					      link_up);
}

static int lw_ethtool_callback_delay(struct teamd_context *ctx, int events,
				     void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct teamd_port *tdport;
	bool link_up;

	tdport = common_ppriv->tdport;
	link_up = team_is_port_link_up(tdport->team_port);
	return teamd_link_watch_check_link_up(ctx, tdport, common_ppriv,
					      link_up);
}

static int lw_ethtool_load_options(struct teamd_context *ctx,
				   struct teamd_port *tdport,
				   struct lw_ethtool_port_priv *ethtool_ppriv)
{
	struct teamd_config_path_cookie *cpcookie = ethtool_ppriv->common.cpcookie;
	int err;
	int tmp;

	err = teamd_config_int_get(ctx, &tmp, "@.delay_up", cpcookie);
	if (!err) {
		if (tmp < 0) {
			teamd_log_err("\"delay_up\" must not be negative number.");
			return -EINVAL;
		}
		teamd_log_dbg(ctx, "delay_up \"%d\".", tmp);
		ms_to_timespec(&ethtool_ppriv->delay_up, tmp);
	}
	err = teamd_config_int_get(ctx, &tmp, "@.delay_down", cpcookie);
	if (!err) {
		if (tmp < 0) {
			teamd_log_err("\"delay_down\" must not be negative number.");
			return -EINVAL;
		}
		teamd_log_dbg(ctx, "delay_down \"%d\".", tmp);
		ms_to_timespec(&ethtool_ppriv->delay_down, tmp);
	}
	return 0;
}

static const struct teamd_event_watch_ops lw_ethtool_port_watch_ops = {
	.port_changed = lw_ethtool_event_watch_port_changed,
};

static int lw_ethtool_port_added(struct teamd_context *ctx,
				 struct teamd_port *tdport,
				 void *priv, void *creator_priv)
{
	int err;

	err = lw_ethtool_load_options(ctx, tdport, priv);
	if (err) {
		teamd_log_err("Failed to load options.");
		return err;
	}
	err = teamd_loop_callback_timer_add(ctx, LW_ETHTOOL_DELAY_CB_NAME,
					    priv, lw_ethtool_callback_delay);
	if (err) {
		teamd_log_err("Failed add delay callback timer");
		return err;
	}
	err = teamd_event_watch_register(ctx, &lw_ethtool_port_watch_ops, priv);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		goto delay_callback_del;
	}
	return 0;

delay_callback_del:
	teamd_loop_callback_del(ctx, LW_ETHTOOL_DELAY_CB_NAME, priv);
	return err;
}

static void lw_ethtool_port_removed(struct teamd_context *ctx,
				    struct teamd_port *tdport,
				    void *priv, void *creator_priv)
{
	teamd_event_watch_unregister(ctx, &lw_ethtool_port_watch_ops, priv);
	teamd_loop_callback_del(ctx, LW_ETHTOOL_DELAY_CB_NAME, priv);
}

static int lw_ethtool_state_delay_up_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct timespec *ts;

	ts = &lw_ethtool_ppriv_get(common_ppriv)->delay_up;
	gsc->data.int_val = timespec_to_ms(ts);
	return 0;
}

static int lw_ethtool_state_delay_down_get(struct teamd_context *ctx,
					   struct team_state_gsc *gsc,
					   void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct timespec *ts;

	ts = &lw_ethtool_ppriv_get(common_ppriv)->delay_down;
	gsc->data.int_val = timespec_to_ms(ts);
	return 0;
}

static const struct teamd_state_val lw_ethtool_state_vals[] = {
	{
		.subpath = "delay_up",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ethtool_state_delay_up_get,
	},
	{
		.subpath = "delay_down",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_ethtool_state_delay_down_get,
	},
};

const struct teamd_link_watch teamd_link_watch_ethtool = {
	.name			= "ethtool",
	.state_vg		= {
		.vals		= lw_ethtool_state_vals,
		.vals_count	= ARRAY_SIZE(lw_ethtool_state_vals),
	},
	.port_priv = {
		.init		= lw_ethtool_port_added,
		.fini		= lw_ethtool_port_removed,
		.priv_size	= sizeof(struct lw_ethtool_port_priv),
	},
};
