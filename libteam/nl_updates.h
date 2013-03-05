/*
 *   lib/nl_updates.h - Updates to libnl which are not synced from kernel yet
 *   Copyright (C) 2012 Jiri Pirko <jpirko@redhat.com>
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

#ifndef _NL_UPDATES_H_
#define _NL_UPDATES_H_

#include <netlink/netlink.h>

#ifndef NLA_BINARY
#define NLA_BINARY 11
#endif

#ifndef NLA_S8
/*
 * Presume that libnl will add all types and relevant puts/gets at once
 * so check only for NLA_S8.
 */
#define NLA_S8 12
#define NLA_S16 13
#define NLA_S32 14
#define NLA_S64 15

/**
 * Add 8 bit signed integer attribute to netlink message.
 * @arg msg		Netlink message.
 * @arg attrtype	Attribute type.
 * @arg value		Numeric value to store as payload.
 *
 * @see nla_put
 * @return 0 on success or a negative error code.
 */
static inline int nla_put_s8(struct nl_msg *msg, int attrtype, int8_t value)
{
	return nla_put(msg, attrtype, sizeof(int8_t), &value);
}

/**
 * Return value of 8 bit signed integer attribute.
 * @arg nla		8 bit signed integer attribute
 *
 * @return Payload as 8 bit signed integer.
 */
int8_t nla_get_s8(struct nlattr *nla)
{
	return *(int8_t *) nla_data(nla);
}

/**
 * Add 16 bit signed integer attribute to netlink message.
 * @arg msg		Netlink message.
 * @arg attrtype	Attribute type.
 * @arg value		Numeric value to store as payload.
 *
 * @see nla_put
 * @return 0 on success or a negative error code.
 */
int nla_put_s16(struct nl_msg *msg, int attrtype, int16_t value)
{
	return nla_put(msg, attrtype, sizeof(int16_t), &value);
}

/**
 * Return payload of 16 bit signed integer attribute.
 * @arg nla		16 bit signed integer attribute
 *
 * @return Payload as 16 bit signed integer.
 */
int16_t nla_get_s16(struct nlattr *nla)
{
	return *(int16_t *) nla_data(nla);
}

/**
 * Add 32 bit signed integer attribute to netlink message.
 * @arg msg		Netlink message.
 * @arg attrtype	Attribute type.
 * @arg value		Numeric value to store as payload.
 *
 * @see nla_put
 * @return 0 on success or a negative error code.
 */
int nla_put_s32(struct nl_msg *msg, int attrtype, int32_t value)
{
	return nla_put(msg, attrtype, sizeof(int32_t), &value);
}

/**
 * Return payload of 32 bit signed integer attribute.
 * @arg nla		32 bit signed integer attribute.
 *
 * @return Payload as 32 bit signed integer.
 */
int32_t nla_get_s32(struct nlattr *nla)
{
	return *(int32_t *) nla_data(nla);
}

/**
 * Add 64 bit signed integer attribute to netlink message.
 * @arg msg		Netlink message.
 * @arg attrtype	Attribute type.
 * @arg value		Numeric value to store as payload.
 *
 * @see nla_put
 * @return 0 on success or a negative error code.
 */
int nla_put_s64(struct nl_msg *msg, int attrtype, int64_t value)
{
	return nla_put(msg, attrtype, sizeof(int64_t), &value);
}

/**
 * Add 8 bit signed integer attribute to netlink message.
 * @arg msg		Netlink message.
 * @arg attrtype	Attribute type.
 * @arg value		Numeric value.
 */
#define NLA_PUT_S8(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, int8_t, attrtype, value)

/**
 * Add 16 bit signed integer attribute to netlink message.
 * @arg msg		Netlink message.
 * @arg attrtype	Attribute type.
 * @arg value		Numeric value.
 */
#define NLA_PUT_S16(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, int16_t, attrtype, value)

/**
 * Add 32 bit signed integer attribute to netlink message.
 * @arg msg		Netlink message.
 * @arg attrtype	Attribute type.
 * @arg value		Numeric value.
 */
#define NLA_PUT_S32(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, int32_t, attrtype, value)

/**
 * Add 64 bit signed integer attribute to netlink message.
 * @arg msg		Netlink message.
 * @arg attrtype	Attribute type.
 * @arg value		Numeric value.
 */
#define NLA_PUT_S64(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, int64_t, attrtype, value)

/**
 * Return payload of u64 attribute
 * @arg nla		u64 netlink attribute
 *
 * @return Payload as 64 bit signed integer.
 */
int64_t nla_get_s64(struct nlattr *nla)
{
	int64_t tmp;

	nla_memcpy(&tmp, nla, sizeof(tmp));

	return tmp;
}

#endif

#endif /* _NL_UPDATES_H_ */
