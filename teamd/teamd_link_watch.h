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

struct lw_psr_port_priv;

struct lw_psr_ops {
	int (*sock_open)(struct lw_psr_port_priv *psr_ppriv);
	void (*sock_close)(struct lw_psr_port_priv *psr_ppriv);
	int (*load_options)(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    struct lw_psr_port_priv *psr_ppriv);
	int (*send)(struct lw_psr_port_priv *psr_ppriv);
	int (*receive)(struct lw_psr_port_priv *psr_ppriv);
};

struct lw_psr_port_priv {
	struct lw_common_port_priv common; /* must be first */
	const struct lw_psr_ops *ops;
	struct timespec interval;
	struct timespec init_wait;
	unsigned int missed_max;
	int sock;
	unsigned int missed;
	bool reply_received;
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

struct lw_psr_port_priv *
lw_psr_ppriv_get(struct lw_common_port_priv *common_ppriv);
int lw_psr_port_added(struct teamd_context *ctx, struct teamd_port *tdport,
		      void *priv, void *creator_priv);
void lw_psr_port_removed(struct teamd_context *ctx, struct teamd_port *tdport,
			 void *priv, void *creator_priv);
int lw_psr_state_interval_get(struct teamd_context *ctx,
			      struct team_state_gsc *gsc,
			      void *priv);
int lw_psr_state_init_wait_get(struct teamd_context *ctx,
			       struct team_state_gsc *gsc,
			       void *priv);
int lw_psr_state_missed_max_get(struct teamd_context *ctx,
			        struct team_state_gsc *gsc,
			        void *priv);
int lw_psr_state_missed_get(struct teamd_context *ctx,
			    struct team_state_gsc *gsc,
			    void *priv);

#endif
