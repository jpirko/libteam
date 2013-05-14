/*
 *   teamd_workq.c - Teamd work queue
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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <private/misc.h>

#include "teamd_workq.h"

#define WORKQ_CB_NAME "workq"

static int teamd_workq_callback_socket(struct teamd_context *ctx, int events,
				       void *priv)
{
	struct teamd_workq *workq;
	struct teamd_workq *tmp;
	char bytes[16];
	int ret;
	int err;

again:
	ret = read(ctx->workq.pipe_r, bytes, sizeof(bytes));
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		else if (errno != EAGAIN)
			return -errno;
	}

	teamd_loop_callback_disable(ctx, WORKQ_CB_NAME, ctx);

	list_for_each_node_entry_safe(workq, tmp, &ctx->workq.work_list, list) {
		list_del(&workq->list);
		err = workq->func(ctx, workq);
		if (err)
			return err;
	}
	return 0;
}

int teamd_workq_init(struct teamd_context *ctx)
{
	int fds[2];
	int err;

	list_init(&ctx->workq.work_list);
	err = pipe2(fds, O_NONBLOCK);
	if (err)
		return -errno;
	ctx->workq.pipe_r = fds[0];
	ctx->workq.pipe_w = fds[1];

	err = teamd_loop_callback_fd_add(ctx, WORKQ_CB_NAME, ctx,
					 teamd_workq_callback_socket,
					 ctx->workq.pipe_r,
					 TEAMD_LOOP_FD_EVENT_READ);
	if (err) {
		teamd_log_err("Failed add workq callback.");
		goto close_pipe;
	}
	return 0;

close_pipe:
	close(ctx->workq.pipe_r);
	close(ctx->workq.pipe_w);
	return 0;
}

void teamd_workq_fini(struct teamd_context *ctx)
{
	struct teamd_workq *workq;
	struct teamd_workq *tmp;

	teamd_loop_callback_del(ctx, WORKQ_CB_NAME, ctx);
	close(ctx->workq.pipe_r);
	close(ctx->workq.pipe_w);
	list_for_each_node_entry_safe(workq, tmp, &ctx->workq.work_list, list)
		list_del(&workq->list);
}

static void teamd_workq_set_for_process(struct teamd_context *ctx)
{
	int err;
	const char byte = 0;

retry:
	err = write(ctx->workq.pipe_w, &byte, 1);
	if (err == -1 && errno == EINTR)
		goto retry;
	teamd_loop_callback_enable(ctx, WORKQ_CB_NAME, ctx);
}

void teamd_workq_schedule(struct teamd_context *ctx, struct teamd_workq *workq)
{
	list_add_tail(&ctx->workq.work_list, &workq->list);
	teamd_workq_set_for_process(ctx);
}
