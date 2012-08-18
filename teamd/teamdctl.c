/*
 *   teamdctl.c - Network team device daemon control tool
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <dbus/dbus.h>
#include <private/misc.h>

#include "teamd_dbus.h"

typedef int (*msg_prepare_t)(char *method_name, DBusMessage *msg,
			     int argc, char **argv);
typedef int (*msg_process_t)(char *method_name, DBusMessage *msg);

#define METHOD_PARAM_MAX_CNT 8

struct method_type {
	char *name;
	char *params[METHOD_PARAM_MAX_CNT];
	msg_prepare_t msg_prepare;
	msg_process_t msg_process;
};

static int noreply_msg_process(char *method_name, DBusMessage *msg)
{
	DBusMessageIter args;
	dbus_bool_t dbres;
	char *param = NULL;

	dbres = dbus_message_iter_init(msg, &args);
	if (dbres == FALSE)
		return 0; /* Success */

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		fprintf(stderr, "%s: Received argument is not string as expected.\n",
			method_name);
		return -EINVAL;
	}
	dbus_message_iter_get_basic(&args, &param);
	fprintf(stderr, "%s: Failed: \"%s\"\n", method_name, param);
	return -EINVAL;
}

static int configdump_msg_prepare(char *method_name, DBusMessage *msg,
				  int argc, char **argv)
{
	return 0;
}

static int configdump_msg_process(char *method_name, DBusMessage *msg)
{
	DBusMessageIter args;
	dbus_bool_t dbres;
	char *param = NULL;

	dbres = dbus_message_iter_init(msg, &args);
	if (dbres == FALSE) {
		fprintf(stderr, "%s: Failed, no data received.\n", method_name);
		return -EINVAL;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		fprintf(stderr, "%s: Received argument is not string as expected.\n",
			method_name);
		return -EINVAL;
	}
	dbus_message_iter_get_basic(&args, &param);
	fprintf(stderr, "%s\n", param);
	return 0;
}

static int portaddrm_msg_prepare(char *method_name, DBusMessage *msg,
				 int argc, char **argv)
{
	DBusMessageIter args;
	dbus_bool_t dbres;

	if (argc < 1) {
		fprintf(stderr, "%s: Port name as a command line parameter expected.\n",
			method_name);
		return -EINVAL;
	}
	dbus_message_iter_init_append(msg, &args);
	dbres = dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					       &argv[0]);
	if (dbres == FALSE) {
		fprintf(stderr, "%s: Failed to construct message.\n",
			method_name);
		return -ENOMEM;
	}
	return 0;
}

static int portconfigupdate_msg_prepare(char *method_name, DBusMessage *msg,
					int argc, char **argv)
{
	DBusMessageIter args;
	dbus_bool_t dbres;

	if (argc < 1) {
		fprintf(stderr, "%s: Port name as a command line parameter expected.\n",
			method_name);
		return -EINVAL;
	}
	if (argc < 2) {
		fprintf(stderr, "%s: Port config as a command line parameter expected.\n",
			method_name);
		return -EINVAL;
	}
	dbus_message_iter_init_append(msg, &args);
	dbres = dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					       &argv[0]);
	if (dbres == FALSE) {
		fprintf(stderr, "%s: Failed to construct message.\n",
			method_name);
		return -ENOMEM;
	}
	dbres = dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					       &argv[1]);
	if (dbres == FALSE) {
		fprintf(stderr, "%s: Failed to construct message.\n",
			method_name);
		return -ENOMEM;
	}
	return 0;
}

static struct method_type method_types[] = {
	{
		.name = "ConfigDump",
		.params = { NULL },
		.msg_prepare = configdump_msg_prepare,
		.msg_process = configdump_msg_process,
	},
	{
		.name = "PortAdd",
		.params = { "PORTDEV", NULL },
		.msg_prepare = portaddrm_msg_prepare,
		.msg_process = noreply_msg_process,
	},
	{
		.name = "PortRemove",
		.params = { "PORTDEV", NULL },
		.msg_prepare = portaddrm_msg_prepare,
		.msg_process = noreply_msg_process,
	},
	{
		.name = "PortConfigUpdate",
		.params = { "PORTDEV", "PORTCONFIG", NULL },
		.msg_prepare = portconfigupdate_msg_prepare,
		.msg_process = noreply_msg_process,
	},
};
#define METHOD_TYPE_COUNT ARRAY_SIZE(method_types)

static int call_method(char *team_devname, char *method_name,
		       int argc, char **argv,
		       msg_prepare_t msg_prepare, msg_process_t msg_process)
{
	int err;
	char *service_name;
	DBusMessage *msg;
	DBusConnection *conn;
	DBusPendingCall *pending;
	DBusError error;
	dbus_bool_t dbres;

	err = asprintf(&service_name, TEAMD_DBUS_SERVICE ".%s", team_devname);
	if (err == -1)
		return -errno;

	dbus_error_init(&error);
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!conn) {
		fprintf(stderr, "Could not acquire the system bus: %s - %s",
			error.name, error.message);
		err = -EINVAL;
		goto free_err;
	}

	msg = dbus_message_new_method_call(service_name, TEAMD_DBUS_PATH,
					   TEAMD_DBUS_IFACE, method_name);
	if (!msg) {
		fprintf(stderr, "Failed to create message.\n");
		err = -ENOMEM;
		goto bus_put;
	}

	err = msg_prepare(method_name, msg, argc, argv);
	if (err) {
		goto free_message;
	}

	dbres = dbus_connection_send_with_reply(conn, msg, &pending, -1);
	if (dbres== FALSE) {
		fprintf(stderr, "Send with reply failed.\n");
		err = -ENOMEM;
		goto free_message;
	}
	if (!pending) {
		fprintf(stderr, "Pending call not created.\n");
		err = -ENOMEM;
		goto free_message;
	}

	dbus_pending_call_block(pending);

	dbus_message_unref(msg);
	msg = dbus_pending_call_steal_reply(pending);
	if (!msg) {
		fprintf(stderr, "Failed to get reply.\n");
	}
	dbus_pending_call_unref(pending);
	if (!msg)
		goto bus_put;

	err = msg_process(method_name, msg);
	if (err) {
		goto free_message;
	}

	err = 0;

free_message:
	dbus_message_unref(msg);
bus_put:
	dbus_connection_unref(conn);
free_err:
	dbus_error_free(&error);
	return err;
}

static void print_help(const char *argv0) {
	int i, j;

	printf(
            "%s [options] teamdevname method [method args]\n"
            "\t-h --help                Show this help\n",
            argv0);
	printf("Methods:\n");
	for (i = 0; i < METHOD_TYPE_COUNT; i++) {
		printf("\t%s", method_types[i].name);
		for (j = 0; method_types[i].params[j]; j++)
			printf(" %s", method_types[i].params[j]);
		printf("\n");
	}
}

int main(int argc, char **argv)
{
	char *argv0 = argv[0];
	char *team_devname;
	char *method_name;
	static const struct option long_options[] = {
		{ "help",		no_argument,		NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	int opt;
	int err;
	int i;

	while ((opt = getopt_long(argc, argv, "h",
				  long_options, NULL)) >= 0) {

		switch(opt) {
		case 'h':
			print_help(argv0);
			return EXIT_SUCCESS;
		case '?':
			fprintf(stderr, "unknown option.\n");
			print_help(argv0);
			return EXIT_FAILURE;
		default:
			fprintf(stderr, "unknown option \"%c\".\n", opt);
			print_help(argv0);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "No team device specified.\n");
		printf("\n");
		print_help(argv0);
		return EXIT_FAILURE;
	}
	if (optind + 1 >= argc) {
		fprintf(stderr, "No method to call specified.\n");
		printf("\n");
		print_help(argv0);
		return EXIT_FAILURE;
	}

	argv += optind;
	team_devname = *argv++;
	method_name = *argv++;
	argc -= optind + 2;
	for (i = 0; i < METHOD_TYPE_COUNT; i++) {
		if (strcmp(method_types[i].name, method_name))
			continue;
		err = call_method(team_devname, method_name, argc, argv,
				  method_types[i].msg_prepare,
				  method_types[i].msg_process);
		if (err) {
			return EXIT_FAILURE;
		}
		break;
	}
	if (i == METHOD_TYPE_COUNT) {
		fprintf(stderr, "Unknown method \"%s\".\n", method_name);
		printf("\n");
		print_help(argv0);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
