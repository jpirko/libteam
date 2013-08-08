/*
 *   teamd_ctl.h - Teamd control subsystem
 *   Copyright (C) 2012-2013 Jiri Pirko <jiri@resnulli.us>
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

#ifndef _TEAMD_CTL_H_
#define _TEAMD_CTL_H_

struct teamd_ctl_method_ops {
	int (*get_args)(void *ops_priv, const char *fmt, ...);
	int (*reply_err)(void *ops_priv, const char *err_code,
			 const char *err_msg);
	int (*reply_succ)(void *ops_priv, const char *msg);
};

bool teamd_ctl_method_exists(const char *method_name);
int teamd_ctl_method_call(struct teamd_context *ctx, const char *method_name,
			  const struct teamd_ctl_method_ops *ops,
			  void *ops_priv);

#endif /* _TEAMD_CTL_H_ */
