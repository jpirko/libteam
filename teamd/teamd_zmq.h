/*
 *   teamd_zmq.h - Teamd ZeroMQ api
 *   Copyright (C) 2013 Jiri Zupka <jzupka@redhat.com>
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

#ifndef _TEAMD_ZMQ_H_
#define _TEAMD_ZMQ_H_

#ifdef ENABLE_ZMQ

int teamd_zmq_init(struct teamd_context *ctx);
void teamd_zmq_fini(struct teamd_context *ctx);

#else

static inline int teamd_zmq_init(struct teamd_context *ctx)
{
	return 0;
}

static inline void teamd_zmq_fini(struct teamd_context *ctx)
{
}

#endif /* ENABLE_ZMQ */

#endif /* _TEAMD_ZMQ_H_ */
