/*
 *   teamd_state.h - Teamd state frontend
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

#ifndef _TEAMD_STATE_H_
#define _TEAMD_STATE_H_

#include "teamd.h"

#define TEAMD_RUNNER_STATE_JSON_NAME "runner"

struct teamd_state_ops {
	int (*dump)(struct teamd_context *ctx,
		    json_t **pstate_json, void *priv);
	int (*per_port_dump)(struct teamd_context *ctx,
			     struct teamd_port *tdport,
			     json_t **pstate_json, void *priv);
	char *name;
};

int teamd_state_init(struct teamd_context *ctx);
void teamd_state_fini(struct teamd_context *ctx);
int teamd_state_ops_register(struct teamd_context *ctx,
			     const struct teamd_state_ops *ops,
			     void *priv);
void teamd_state_ops_unregister(struct teamd_context *ctx,
				const struct teamd_state_ops *ops,
				void *priv);
int teamd_state_dump(struct teamd_context *ctx, char **p_state_dump);

int teamd_state_basics_init(struct teamd_context *ctx);
void teamd_state_basics_fini(struct teamd_context *ctx);

#endif /* _TEAMD_STATE_H_ */
