#ifndef _TEAMD_LINK_WATCH_H_
#define _TEAMD_LINK_WATCH_H_

#include "teamd_state.h"

struct teamd_link_watch {
	const char *name;
	const struct teamd_state_val state_vg;
	struct teamd_port_priv port_priv;
};

struct lw_common_port_priv {
	unsigned int id;
	const struct teamd_link_watch *link_watch;
	struct teamd_context *ctx;
	struct teamd_port *tdport;
	bool link_up;
	bool forced_send;
	struct teamd_config_path_cookie *cpcookie;
};

static inline bool teamd_link_watch_link_up_differs(struct lw_common_port_priv *common_ppriv,
					     bool new_link_up)
{
	return new_link_up != common_ppriv->link_up;
}

int teamd_link_watch_check_link_up(struct teamd_context *ctx,
				   struct teamd_port *tdport,
				   struct lw_common_port_priv *common_ppriv,
				   bool new_link_up);

#endif
