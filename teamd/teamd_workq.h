/*
 *   teamd_workq.h - Teamd work queue
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

#ifndef _TEAMD_WORKQ_H_
#define _TEAMD_WORKQ_H_

#include "teamd.h"

struct teamd_workq;
typedef int (*teamd_workq_func_t)(struct teamd_context *ctx,
				  struct teamd_workq *workq);
struct teamd_workq {
	struct list_item list;
	teamd_workq_func_t func;
};

int teamd_workq_init(struct teamd_context *ctx);
void teamd_workq_fini(struct teamd_context *ctx);
void teamd_workq_schedule_work(struct teamd_context *ctx,
			       struct teamd_workq *workq);
void teamd_workq_init_work(struct teamd_workq *workq, teamd_workq_func_t func);

#endif /* _TEAMD_WORKQ_H_ */
