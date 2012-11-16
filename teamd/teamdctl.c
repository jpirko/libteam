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
#include <jansson.h>
#include <private/misc.h>

#include "teamd_dbus.h"

enum verbosity_level {
	VERB1,
	VERB2,
	VERB3,
	VERB4,
};

#define DEFAULT_VERB VERB1
static int g_verbosity = DEFAULT_VERB;
static int g_indent_level = 0;
#define INDENT_STR_STEP 2
#define INDENT_STR_MAXLEN 32
static char g_indent_str[INDENT_STR_MAXLEN + 1] = "";

static void pr_out_indent_inc(void)
{
	if (g_indent_level + INDENT_STR_STEP > INDENT_STR_MAXLEN)
		return;
	g_indent_level += INDENT_STR_STEP;
	memset(g_indent_str, ' ', sizeof(g_indent_str));
	g_indent_str[g_indent_level] = '\0';
}

static void pr_out_indent_dec(void)
{
	if (g_indent_level - INDENT_STR_STEP < 0)
		return;
	g_indent_level -= INDENT_STR_STEP;
	g_indent_str[g_indent_level] = '\0';
}

#define pr_err(args...) fprintf(stderr, ##args)
#define pr_outx(verb_level, args...) \
	if (verb_level <= g_verbosity) { \
		fprintf(stdout, g_indent_str); \
		fprintf(stdout, ##args); \
	}
#define pr_out(args...) pr_outx(DEFAULT_VERB, ##args)
#define pr_out2(args...) pr_outx(VERB2, ##args)
#define pr_out3(args...) pr_outx(VERB3, ##args)
#define pr_out4(args...) pr_outx(VERB4, ##args)


typedef int (*msg_prepare_t)(char *cmd_name, DBusMessage *msg,
			     int argc, char **argv);
typedef int (*msg_process_t)(char *cmd_name, DBusMessage *msg);

#define COMMAND_PARAM_MAX_CNT 8

struct command_type {
	char *name;
	char *dbus_method_name;
	char *params[COMMAND_PARAM_MAX_CNT];
	msg_prepare_t msg_prepare;
	msg_process_t msg_process;
};

static int check_error_msg(char *cmd_name, DBusMessage *msg)
{
	DBusMessageIter args;
	dbus_bool_t dbres;
	char *param = NULL;
	const char *err_msg;

	err_msg = dbus_message_get_error_name(msg);
	if (!err_msg)
		return 0;
	pr_err("%s: Error message received: \"%s\"\n", cmd_name, err_msg);

	dbres = dbus_message_iter_init(msg, &args);
	if (dbres == TRUE) {
		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
			pr_err("%s: Received argument is not string as expected.\n",
			       cmd_name);
			return -EINVAL;
		}
		dbus_message_iter_get_basic(&args, &param);
		pr_err("%s: Error message content: \"%s\"\n",
		       cmd_name, param);
	}
	return -EINVAL;
}

static int noreply_msg_process(char *cmd_name, DBusMessage *msg)
{
	return check_error_msg(cmd_name, msg);
}

static int norequest_msg_prepare(char *cmd_name, DBusMessage *msg,
				 int argc, char **argv)
{
	return 0;
}

static int stringdump_msg_process(char *cmd_name, DBusMessage *msg)
{
	DBusMessageIter args;
	dbus_bool_t dbres;
	char *param = NULL;
	int err;

	err = check_error_msg(cmd_name, msg);
	if (err)
		return err;
	dbres = dbus_message_iter_init(msg, &args);
	if (dbres == FALSE) {
		pr_err("%s: Failed, no data received.\n", cmd_name);
		return -EINVAL;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		pr_err("%s: Received argument is not string as expected.\n",
		       cmd_name);
		return -EINVAL;
	}
	dbus_message_iter_get_basic(&args, &param);
	pr_out("%s\n", param);
	return 0;
}

#define boolyesno(val) (val ? "yes" : "no")
#define boolupdown(val) (val ? "up" : "down")

static int stateview_json_setup_process(char *cmd_name, char **prunner_name,
					json_t *setup_json)
{
	int err;
	char *runner_name;
	char *kernel_team_mode_name;
	int dbus_enabled;
	int debug_level;
	int daemonized;
	int pid;
	char *pid_file;

	pr_out("setup:\n");
	err = json_unpack(setup_json, "{s:s, s:s, s:b, s:i, s:b, s:i, s:s}",
			  "runner_name", &runner_name,
			  "kernel_team_mode_name", &kernel_team_mode_name,
			  "dbus_enabled", &dbus_enabled,
			  "debug_level", &debug_level,
			  "daemonized", &daemonized,
			  "pid", &pid,
			  "pid_file", &pid_file);
	if (err) {
		pr_err("%s: Failed to parse JSON setup dump.\n",
		       cmd_name);
		return -EINVAL;
	}
	pr_out_indent_inc();
	pr_out("runner: %s\n", runner_name);
	pr_out2("kernel team mode: %s\n", kernel_team_mode_name);
	pr_out2("D-BUS enabled: %s\n", boolyesno(dbus_enabled));
	pr_out2("debug level: %d\n", debug_level);
	pr_out2("daemonized: %s\n", boolyesno(daemonized));
	pr_out2("PID: %d\n", pid);
	pr_out2("PID file: %s\n", pid_file);
	pr_out_indent_dec();

	*prunner_name = runner_name;
	return 0;
}

static int stateview_json_link_watch_info_process(char *cmd_name,
						  char *lw_name,
						  json_t *lw_info_json)
{
	int err;

	if (!strcmp(lw_name, "ethtool")) {
		int delay_up;
		int delay_down;

		err = json_unpack(lw_info_json, "{s:i, s:i}",
				  "delay_up", &delay_up,
				  "delay_down", &delay_down);
		if (err) {
			pr_err("%s: Failed to parse JSON ethtool link watch info dump.\n",
			       cmd_name);
			return -EINVAL;
		}
		pr_out2("link up delay: %d\n", delay_up);
		pr_out2("link down delay: %d\n", delay_down);
	} else if (!strcmp(lw_name, "arp_ping")) {
		char *source_host;
		char *target_host;
		int interval;
		int init_wait;
		int validate;
		int always_active;
		int missed_max;
		int missed;

		err = json_unpack(lw_info_json, "{s:s, s:s, s:i, s:i, s:b, s:b, s:i, s:i}",
				  "source_host", &source_host,
				  "target_host", &target_host,
				  "interval", &interval,
				  "init_wait", &init_wait,
				  "validate", &validate,
				  "always_active", &always_active,
				  "missed_max", &missed_max,
				  "missed", &missed);
		if (err) {
			pr_err("%s: Failed to parse JSON arp_ping link watch info dump.\n",
			       cmd_name);
			return -EINVAL;
		}
		pr_out2("source host: %s\n", source_host);
		pr_out2("target host: %s\n", target_host);
		pr_out2("interval: %d\n", interval);
		pr_out2("missed packets: %d/%d\n", missed, missed_max);
		pr_out2("validate: %s\n", boolyesno(validate));
		pr_out2("always active: %s\n", boolyesno(always_active));
		pr_out2("initial wait: %d\n", init_wait);
	} else if (!strcmp(lw_name, "nsna_ping")) {
		char *target_host;
		int interval;
		int init_wait;
		int missed_max;
		int missed;

		err = json_unpack(lw_info_json, "{s:s, s:i, s:i, s:i, s:i}",
				  "target_host", &target_host,
				  "interval", &interval,
				  "init_wait", &init_wait,
				  "missed_max", &missed_max,
				  "missed", &missed);
		if (err) {
			pr_err("%s: Failed to parse JSON nsna_ping link watch info dump.\n",
			       cmd_name);
			return -EINVAL;
		}
		pr_out2("target host: %s\n", target_host);
		pr_out2("interval: %d\n", interval);
		pr_out2("missed packets: %d/%d\n", missed, missed_max);
		pr_out2("initial wait: %d\n", init_wait);
	} else {
		pr_err("%s: Failed to parse JSON unknown link watch info dump.\n",
		       cmd_name);
		return -EINVAL;
	}
	return 0;
}

static int stateview_json_port_link_watches_process(char *cmd_name,
						    json_t *port_link_watches_json)
{
	int err;
	int up;
	json_t *lw_list_json;
	json_t *lw_json;
	json_t *lw_info_json;
	char *lw_name;
	int i;

	err = json_unpack(port_link_watches_json, "{s:b, s:o}",
			  "up", &up, "list", &lw_list_json);
	if (err) {
		pr_err("%s: Failed to parse JSON port link watches dump.\n",
		       cmd_name);
		return -EINVAL;
	}
	pr_out("link watches:\n");
	pr_out_indent_inc();
	pr_out("link summary: %s\n", boolupdown(up));
	i = 0;
	while (i < json_array_size(lw_list_json)) {
		lw_json = json_array_get(lw_list_json, i);

		err = json_unpack(lw_json, "{s:b, s:s, s:o}",
				  "up", &up,
				  "name", &lw_name,
				  "info", &lw_info_json);
		if (err) {
			pr_err("%s: Failed to parse JSON port link watch dump.\n",
			       cmd_name);
			return -EINVAL;
		}
		pr_out("intance[%d]:\n", i);
		pr_out_indent_inc();
		pr_out("name: %s\n", lw_name);
		pr_out("link: %s\n", boolupdown(up));
		pr_out2("info:\n");
		pr_out_indent_inc();
		err = stateview_json_link_watch_info_process(cmd_name,
							     lw_name,
							     lw_info_json);
		if (err)
			return err;
		pr_out_indent_dec();
		pr_out_indent_dec();
		i++;
	}
	pr_out_indent_dec();
	return 0;
}

static int stateview_json_lacpdu_process(char *cmd_name,
					 json_t *lacpdu_json)
{
	int err;
	int system_priority;
	char *system;
	int key;
	int port_priority;
	int port;
	int state;

	err = json_unpack(lacpdu_json, "{s:i, s:s, s:i, s:i, s:i, s:i}",
			 "system_priority", &system_priority,
			 "system", &system,
			 "key", &key,
			 "port_priority", &port_priority,
			 "port", &port,
			 "state", &state);
	if (err) {
		pr_err("%s: Failed to parse JSON port runner lacpdu dump.\n",
		       cmd_name);
		return -EINVAL;
	}
	pr_out2("system priority: %d\n", system_priority);
	pr_out2("system: %s\n", system);
	pr_out2("key: %d\n", key);
	pr_out2("port_priority: %d\n", port_priority);
	pr_out2("port: %d\n", port);
	pr_out2("state: 0x%x\n", state);
	return 0;
}

static int stateview_json_port_runner_process(char *cmd_name,
					      char *runner_name,
					      json_t *port_json)
{
	int err;

	if (!strcmp(runner_name, "lacp")) {
		int selected;
		int aggregator_id;
		char *state;
		int key;
		int prio;
		json_t *actor_json;
		json_t *partner_json;

		pr_out("runner:\n");
		err = json_unpack(port_json,
				  "{s:{s:b, s:i, s:s, s:i, s:i, s:o, s:o}}",
				  "runner",
				  "selected", &selected,
				  "aggregator_id", &aggregator_id,
				  "state", &state,
				  "key", &key,
				  "prio", &prio,
				  "actor_lacpdu_info", &actor_json,
				  "partner_lacpdu_info", &partner_json);
		if (err) {
			pr_err("%s: Failed to parse JSON port runner dump.\n",
			       cmd_name);
			return -EINVAL;
		}
		pr_out_indent_inc();
		pr_out("aggregator ID: %d\n", aggregator_id);
		pr_out("selected: %s\n", boolyesno(selected));
		pr_out("state: %s\n", state);
		pr_out2("key: %d\n", key);
		pr_out2("priority: %d\n", prio);
		pr_out2("actor LACPDU info:\n");
		pr_out_indent_inc();
		err = stateview_json_lacpdu_process(cmd_name, actor_json);
		if (err)
			return err;
		pr_out_indent_dec();
		pr_out2("partner LACPDU info:\n");
		pr_out_indent_inc();
		err = stateview_json_lacpdu_process(cmd_name, partner_json);
		if (err)
			return err;
		pr_out_indent_dec();
		pr_out_indent_dec();
	}
	return 0;
}

static int stateview_json_port_process(char *cmd_name, char *runner_name,
				       const char *port_name, json_t *port_json)
{
	int err;
	char *dev_addr;
	int dev_addr_len;
	int ifindex;
	char *ifname;
	char *duplex;
	int speed;
	int up;
	json_t *port_link_watches_json;

	err = json_unpack(port_json,
			  "{s:{s:s, s:i, s:i, s:s}, s:{s:s, s:i, s:b}, s:o}",
			  "ifinfo",
			  "dev_addr", &dev_addr,
			  "dev_addr_len", &dev_addr_len,
			  "ifindex", &ifindex,
			  "ifname", &ifname,
			  "link",
			  "duplex", &duplex,
			  "speed", &speed,
			  "up", &up,
			  "link_watches", &port_link_watches_json);
	if (err) {
		pr_err("%s: Failed to parse JSON port dump.\n",
		       cmd_name);
		return -EINVAL;
	}
	pr_out("%s\n", port_name);
	pr_out_indent_inc();
	pr_out2("ifindex: %d\n", ifindex);
	pr_out2("addr: %s\n", dev_addr);
	pr_out2("ethtool link: %dmbit/%sduplex/%s\n", speed, duplex,
						      boolupdown(up));
	err = stateview_json_port_link_watches_process(cmd_name,
						       port_link_watches_json);
	if (err)
		goto err_out;
	err = stateview_json_port_runner_process(cmd_name, runner_name,
						 port_json);
	pr_out_indent_dec();
err_out:
	return err;
}

static int stateview_json_ports_process(char *cmd_name, char *runner_name,
					json_t *ports_json)
{
	int err;
	json_t *iter;

	pr_err("ports:\n");
	for (iter = json_object_iter(ports_json); iter;
	     iter = json_object_iter_next(ports_json, iter)) {
		const char *port_name = json_object_iter_key(iter);
		json_t *port_json = json_object_iter_value(iter);

		pr_out_indent_inc();
		err = stateview_json_port_process(cmd_name, runner_name,
						  port_name, port_json);
		if (err)
			return err;
		pr_out_indent_dec();
	}
	return 0;
}

static int stateview_json_runner_process(char *cmd_name, char *runner_name,
					 json_t *json)
{
	int err;

	if (!strcmp(runner_name, "activebackup")) {
		char *active_port;

		pr_out("runner:\n");
		err = json_unpack(json, "{s:{s:s}}", "runner",
				  "active_port", &active_port);
		if (err) {
			pr_err("%s: Failed to parse JSON runner dump.\n",
			       cmd_name);
			return -EINVAL;
		}
		pr_out_indent_inc();
		pr_out("active port: %s\n", active_port);
		pr_out_indent_dec();
	} else if (!strcmp(runner_name, "lacp")) {
		int selected_aggregator_id;
		int active;
		int sys_prio;
		int fast_rate;

		pr_out("runner:\n");
		err = json_unpack(json, "{s:{s:i, s:b, s:i, s:b}}", "runner",
				  "selected_aggregator_id",
				  &selected_aggregator_id,
				  "active", &active,
				  "sys_prio", &sys_prio,
				  "fast_rate", &fast_rate);
		if (err) {
			pr_err("%s: Failed to parse JSON runner dump.\n",
			       cmd_name);
			return -EINVAL;
		}
		pr_out_indent_inc();
		pr_out("selected aggregator ID: %d\n", selected_aggregator_id);
		pr_out("active: %s\n", boolyesno(active));
		pr_out("fast rate: %s\n", boolyesno(fast_rate));
		pr_out2("system priority: %d\n", sys_prio);
		pr_out_indent_dec();
	}
	return 0;
}

static int stateview_json_process(char *cmd_name, char *dump)
{
	int err;
	char *runner_name;
	json_t *json;
	json_t *setup_json;
	json_t *ports_json;
	json_error_t jerror;

	json = json_loads(dump, JSON_REJECT_DUPLICATES, &jerror);
	if (!json)
		goto parseerr;

	err = json_unpack(json, "{s:o, s:o}", "setup", &setup_json,
					      "ports", &ports_json);
	if (err)
		goto parseerr;
	err = stateview_json_setup_process(cmd_name, &runner_name,
					   setup_json);
	if (err)
		return err;
	err = stateview_json_ports_process(cmd_name, runner_name,
					   ports_json);
	if (err)
		return err;
	err = stateview_json_runner_process(cmd_name, runner_name,
					    json);
	if (err)
		return err;

	return 0;

parseerr:
	pr_err("%s: Failed to parse JSON dump.\n", cmd_name);
	return -EINVAL;
}

static int stateview_msg_process(char *cmd_name, DBusMessage *msg)
{
	DBusMessageIter args;
	dbus_bool_t dbres;
	char *param = NULL;

	dbres = dbus_message_iter_init(msg, &args);
	if (dbres == FALSE) {
		pr_err("%s: Failed, no data received.\n", cmd_name);
		return -EINVAL;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		pr_err("%s: Received argument is not string as expected.\n",
		       cmd_name);
		return -EINVAL;
	}
	dbus_message_iter_get_basic(&args, &param);
	return stateview_json_process(cmd_name, param);
}

static int portaddrm_msg_prepare(char *cmd_name, DBusMessage *msg,
				 int argc, char **argv)
{
	DBusMessageIter args;
	dbus_bool_t dbres;

	if (argc < 1) {
		pr_err("%s: Port name as a command line parameter expected.\n",
		       cmd_name);
		return -EINVAL;
	}
	dbus_message_iter_init_append(msg, &args);
	dbres = dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					       &argv[0]);
	if (dbres == FALSE) {
		pr_err("%s: Failed to construct message.\n", cmd_name);
		return -ENOMEM;
	}
	return 0;
}

static int portconfigupdate_msg_prepare(char *cmd_name, DBusMessage *msg,
					int argc, char **argv)
{
	DBusMessageIter args;
	dbus_bool_t dbres;

	if (argc < 1) {
		pr_err("%s: Port name as a command line parameter expected.\n",
		       cmd_name);
		return -EINVAL;
	}
	if (argc < 2) {
		pr_err("%s: Port config as a command line parameter expected.\n",
		       cmd_name);
		return -EINVAL;
	}
	dbus_message_iter_init_append(msg, &args);
	dbres = dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					       &argv[0]);
	if (dbres == FALSE) {
		pr_err("%s: Failed to construct message.\n", cmd_name);
		return -ENOMEM;
	}
	dbres = dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					       &argv[1]);
	if (dbres == FALSE) {
		pr_err("%s: Failed to construct message.\n", cmd_name);
		return -ENOMEM;
	}
	return 0;
}

static struct command_type command_types[] = {
	{
		.name = "ConfigDump",
		.dbus_method_name = "ConfigDump",
		.params = { NULL },
		.msg_prepare = norequest_msg_prepare,
		.msg_process = stringdump_msg_process,
	},
	{
		.name = "StateDump",
		.dbus_method_name = "StateDump",
		.params = { NULL },
		.msg_prepare = norequest_msg_prepare,
		.msg_process = stringdump_msg_process,
	},
	{
		.name = "StateView",
		.dbus_method_name = "StateDump",
		.params = { NULL },
		.msg_prepare = norequest_msg_prepare,
		.msg_process = stateview_msg_process,
	},
	{
		.name = "PortAdd",
		.dbus_method_name = "PortAdd",
		.params = { "PORTDEV", NULL },
		.msg_prepare = portaddrm_msg_prepare,
		.msg_process = noreply_msg_process,
	},
	{
		.name = "PortRemove",
		.dbus_method_name = "PortRemove",
		.params = { "PORTDEV", NULL },
		.msg_prepare = portaddrm_msg_prepare,
		.msg_process = noreply_msg_process,
	},
	{
		.name = "PortConfigUpdate",
		.dbus_method_name = "PortConfigUpdate",
		.params = { "PORTDEV", "PORTCONFIG", NULL },
		.msg_prepare = portconfigupdate_msg_prepare,
		.msg_process = noreply_msg_process,
	},
};
#define COMMAND_TYPE_COUNT ARRAY_SIZE(command_types)

static int call_command(char *team_devname, int argc, char **argv,
			struct command_type *command_type)
{
	int err;
	char *service_name;
	DBusMessage *msg;
	DBusConnection *conn;
	DBusPendingCall *pending;
	DBusError error;
	dbus_bool_t dbres;
	msg_prepare_t msg_prepare = command_type->msg_prepare;
	msg_process_t msg_process = command_type->msg_process;

	err = asprintf(&service_name, TEAMD_DBUS_SERVICE ".%s", team_devname);
	if (err == -1)
		return -errno;

	dbus_error_init(&error);
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!conn) {
		pr_err("Could not acquire the system bus: %s - %s",
		       error.name, error.message);
		err = -EINVAL;
		goto free_err;
	}

	msg = dbus_message_new_method_call(service_name, TEAMD_DBUS_PATH,
					   TEAMD_DBUS_IFACE,
					   command_type->dbus_method_name);
	if (!msg) {
		pr_err("Failed to create message.\n");
		err = -ENOMEM;
		goto bus_put;
	}

	err = msg_prepare(command_type->name, msg, argc, argv);
	if (err) {
		goto free_message;
	}

	dbres = dbus_connection_send_with_reply(conn, msg, &pending, -1);
	if (dbres== FALSE) {
		pr_err("Send with reply failed.\n");
		err = -ENOMEM;
		goto free_message;
	}
	if (!pending) {
		pr_err("Pending call not created.\n");
		err = -ENOMEM;
		goto free_message;
	}

	dbus_pending_call_block(pending);

	dbus_message_unref(msg);
	msg = dbus_pending_call_steal_reply(pending);
	if (!msg) {
		pr_err("Failed to get reply.\n");
	}
	dbus_pending_call_unref(pending);
	if (!msg)
		goto bus_put;

	err = msg_process(command_type->name, msg);
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

	pr_out(
            "%s [options] teamdevname command [command args]\n"
            "\t-h --help                Show this help\n"
            "\t-v --verbose             Increase verbosity\n",
            argv0);
	pr_out("Commands:\n");
	for (i = 0; i < COMMAND_TYPE_COUNT; i++) {
		pr_out("\t%s", command_types[i].name);
		for (j = 0; command_types[i].params[j]; j++)
			pr_out(" %s", command_types[i].params[j]);
		pr_out("\n");
	}
}

int main(int argc, char **argv)
{
	char *argv0 = argv[0];
	char *team_devname;
	char *cmd_name;
	static const struct option long_options[] = {
		{ "help",		no_argument,		NULL, 'h' },
		{ "verbose",		no_argument,		NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	int opt;
	int err;
	int i;

	while ((opt = getopt_long(argc, argv, "hv",
				  long_options, NULL)) >= 0) {

		switch(opt) {
		case 'h':
			print_help(argv0);
			return EXIT_SUCCESS;
		case 'v':
			g_verbosity++;
			break;
		case '?':
			pr_err("unknown option.\n");
			print_help(argv0);
			return EXIT_FAILURE;
		default:
			pr_err("unknown option \"%c\".\n", opt);
			print_help(argv0);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		pr_err("No team device specified.\n");
		print_help(argv0);
		return EXIT_FAILURE;
	}
	if (optind + 1 >= argc) {
		pr_err("No command specified.\n");
		print_help(argv0);
		return EXIT_FAILURE;
	}

	argv += optind;
	team_devname = *argv++;
	cmd_name = *argv++;
	argc -= optind + 2;
	for (i = 0; i < COMMAND_TYPE_COUNT; i++) {
		if (strncasecmp(command_types[i].name, cmd_name,
				strlen(cmd_name)))
			continue;
		err = call_command(team_devname, argc, argv, &command_types[i]);
		if (err) {
			return EXIT_FAILURE;
		}
		break;
	}
	if (i == COMMAND_TYPE_COUNT) {
		pr_err("Unknown command \"%s\".\n", cmd_name);
		print_help(argv0);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
