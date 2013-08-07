/*
 *   teamdctl.c - Network team device daemon control tool
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <jansson.h>
#include <private/misc.h>
#include <teamdctl.h>

#include "config.h"

enum verbosity_level {
	VERB1,
	VERB2,
	VERB3,
	VERB4,
};

static bool g_oneline = false;
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
		fprintf(stdout, "%s", g_indent_str); \
		fprintf(stdout, ##args); \
	}
#define pr_out(args...) pr_outx(DEFAULT_VERB, ##args)
#define pr_out2(args...) pr_outx(VERB2, ##args)
#define pr_out3(args...) pr_outx(VERB3, ##args)
#define pr_out4(args...) pr_outx(VERB4, ##args)

static int __jsonload(json_t **pjson, char *inputstrjson)
{
	json_t *json;
	json_error_t jerror;

	json = json_loads(inputstrjson, JSON_REJECT_DUPLICATES, &jerror);
	if (!json) {
		pr_err("Failed to parse JSON dump.\n");
		return -EINVAL;
	}
	*pjson = json;
	return 0;
}

static int __jsondump(json_t *json)
{
	char *dump;
	int indent = g_oneline ? 0 : 4;

	dump = json_dumps(json, JSON_INDENT(indent) | JSON_ENSURE_ASCII |
				JSON_SORT_KEYS);
	if (!dump) {
		pr_err("Failed to get JSON dump.\n");
		return -ENOMEM;
	}
	pr_out("%s\n", dump);
	free(dump);
	return 0;
}

static int __jsonloaddump(char *inputstrjson)
{
	int err;
	json_t *json;

	err = __jsonload(&json, inputstrjson);
	if (err)
		return err;
	err = __jsondump(json);
	json_decref(json);
	return err;
}

static int jsonsimpledump_process_reply(char *reply)
{
	return __jsonloaddump(reply);
}

static int noportsdump_json_process(char *dump)
{
	int err;
	json_t *json;

	err = __jsonload(&json, dump);
	if (err)
		return err;
	json_object_del(json, "ports");
	err = __jsondump(json);
	json_decref(json);
	return err;
}

static int jsonnoportsdump_process_reply(char *reply)
{
	return noportsdump_json_process(reply);
}

#define boolyesno(val) (val ? "yes" : "no")
#define boolupdown(val) (val ? "up" : "down")

static int stateview_json_setup_process(char **prunner_name, json_t *dump_json)
{
	int err;
	char *runner_name;
	char *kernel_team_mode_name;
	int dbus_enabled;
	int zmq_enabled;
	int debug_level;
	int daemonized;
	int pid;
	char *pid_file;

	pr_out("setup:\n");
	err = json_unpack(dump_json, "{s:{s:s, s:s, s:b, s:b, s:i, s:b, s:i, s:s}}",
			  "setup",
			  "runner_name", &runner_name,
			  "kernel_team_mode_name", &kernel_team_mode_name,
			  "dbus_enabled", &dbus_enabled,
			  "zmq_enabled", &zmq_enabled,
			  "debug_level", &debug_level,
			  "daemonized", &daemonized,
			  "pid", &pid,
			  "pid_file", &pid_file);
	if (err) {
		pr_err("Failed to parse JSON setup dump.\n");
		return -EINVAL;
	}
	pr_out_indent_inc();
	pr_out("runner: %s\n", runner_name);
	pr_out2("kernel team mode: %s\n", kernel_team_mode_name);
	pr_out2("D-BUS enabled: %s\n", boolyesno(dbus_enabled));
	pr_out2("ZeroMQ enabled: %s\n", boolyesno(zmq_enabled));
	pr_out2("debug level: %d\n", debug_level);
	pr_out2("daemonized: %s\n", boolyesno(daemonized));
	pr_out2("PID: %d\n", pid);
	pr_out2("PID file: %s\n", pid_file);
	pr_out_indent_dec();

	*prunner_name = runner_name;
	return 0;
}

static int stateview_json_link_watch_info_process(char *lw_name,
						  json_t *lw_json)
{
	int err;

	if (!strcmp(lw_name, "ethtool")) {
		int delay_up;
		int delay_down;

		err = json_unpack(lw_json, "{s:i, s:i}",
				  "delay_up", &delay_up,
				  "delay_down", &delay_down);
		if (err) {
			pr_err("Failed to parse JSON ethtool link watch dump.\n");
			return -EINVAL;
		}
		pr_out2("link up delay: %d\n", delay_up);
		pr_out2("link down delay: %d\n", delay_down);
	} else if (!strcmp(lw_name, "arp_ping")) {
		char *source_host;
		char *target_host;
		int interval;
		int init_wait;
		int validate_active;
		int validate_inactive;
		int send_always;
		int missed_max;
		int missed;

		err = json_unpack(lw_json, "{s:s, s:s, s:i, s:i, s:b, s:b, s:b, s:i, s:i}",
				  "source_host", &source_host,
				  "target_host", &target_host,
				  "interval", &interval,
				  "init_wait", &init_wait,
				  "validate_active", &validate_active,
				  "validate_inactive", &validate_inactive,
				  "send_always", &send_always,
				  "missed_max", &missed_max,
				  "missed", &missed);
		if (err) {
			pr_err("Failed to parse JSON arp_ping link watch dump.\n");
			return -EINVAL;
		}
		pr_out2("source host: %s\n", source_host);
		pr_out2("target host: %s\n", target_host);
		pr_out2("interval: %d\n", interval);
		pr_out2("missed packets: %d/%d\n", missed, missed_max);
		pr_out2("validate_active: %s\n", boolyesno(validate_active));
		pr_out2("validate_inactive: %s\n", boolyesno(validate_inactive));
		pr_out2("send_always: %s\n", boolyesno(send_always));
		pr_out2("initial wait: %d\n", init_wait);
	} else if (!strcmp(lw_name, "nsna_ping")) {
		char *target_host;
		int interval;
		int init_wait;
		int missed_max;
		int missed;

		err = json_unpack(lw_json, "{s:s, s:i, s:i, s:i, s:i}",
				  "target_host", &target_host,
				  "interval", &interval,
				  "init_wait", &init_wait,
				  "missed_max", &missed_max,
				  "missed", &missed);
		if (err) {
			pr_err("Failed to parse JSON nsna_ping link watch dump.\n");
			return -EINVAL;
		}
		pr_out2("target host: %s\n", target_host);
		pr_out2("interval: %d\n", interval);
		pr_out2("missed packets: %d/%d\n", missed, missed_max);
		pr_out2("initial wait: %d\n", init_wait);
	} else {
		pr_err("Failed to parse JSON unknown link watch info dump.\n");
		return -EINVAL;
	}
	return 0;
}

static int stateview_json_port_link_watches_list_process(json_t *port_link_watches_json)
{
	int err;
	int up;
	json_t *lw_list_json;
	json_t *lw_json;
	char *lw_name;
	const char *key;

	err = json_unpack(port_link_watches_json, "{s:o}", "list", &lw_list_json);
	if (err)
		return 0;
	json_object_foreach(lw_list_json, key, lw_json) {
		err = json_unpack(lw_json, "{s:b, s:s}",
				  "up", &up, "name", &lw_name);
		if (err) {
			pr_err("Failed to parse JSON port link watch dump.\n");
			return -EINVAL;
		}
		pr_out("instance[%s]:\n", key);
		pr_out_indent_inc();
		pr_out("name: %s\n", lw_name);
		pr_out("link: %s\n", boolupdown(up));
		err = stateview_json_link_watch_info_process(lw_name,
							     lw_json);
		if (err)
			return err;
		pr_out_indent_dec();
	}
	return 0;
}

static int stateview_json_port_link_watches_process(json_t *port_link_watches_json)
{
	int err;
	int up;

	err = json_unpack(port_link_watches_json, "{s:b}", "up", &up);
	if (err) {
		pr_err("Failed to parse JSON port link watches dump.\n");
		return -EINVAL;
	}
	pr_out("link watches:\n");
	pr_out_indent_inc();
	pr_out("link summary: %s\n", boolupdown(up));
	err = stateview_json_port_link_watches_list_process(port_link_watches_json);
	if (err)
		return err;
	pr_out_indent_dec();
	return 0;
}

static int stateview_json_lacpdu_process(json_t *lacpdu_json)
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
		pr_err("Failed to parse JSON port runner lacpdu dump.\n");
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

static int stateview_json_port_runner_process(char *runner_name,
					      json_t *port_json)
{
	int err;

	if (!strcmp(runner_name, "lacp")) {
		int selected;
		int aggregator_id;
		int aggregator_selected;
		char *state;
		int key;
		int prio;
		json_t *actor_json;
		json_t *partner_json;

		pr_out("runner:\n");
		err = json_unpack(port_json,
				  "{s:{s:b, s:{s:i, s:b}, s:s, s:i, s:i, s:o, s:o}}",
				  "runner",
				  "selected", &selected,
				  "aggregator", "id", &aggregator_id,
				  "selected", &aggregator_selected,
				  "state", &state,
				  "key", &key,
				  "prio", &prio,
				  "actor_lacpdu_info", &actor_json,
				  "partner_lacpdu_info", &partner_json);
		if (err) {
			pr_err("Failed to parse JSON port runner dump.\n");
			return -EINVAL;
		}
		pr_out_indent_inc();
		pr_out("aggregator ID: %d%s\n", aggregator_id,
						aggregator_selected ? ", Selected" : "");
		pr_out("selected: %s\n", boolyesno(selected));
		pr_out("state: %s\n", state);
		pr_out2("key: %d\n", key);
		pr_out2("priority: %d\n", prio);
		pr_out2("actor LACPDU info:\n");
		pr_out_indent_inc();
		err = stateview_json_lacpdu_process(actor_json);
		if (err)
			return err;
		pr_out_indent_dec();
		pr_out2("partner LACPDU info:\n");
		pr_out_indent_inc();
		err = stateview_json_lacpdu_process(partner_json);
		if (err)
			return err;
		pr_out_indent_dec();
		pr_out_indent_dec();
	}
	return 0;
}

static int stateview_json_port_process(char *runner_name, const char *port_name,
				       json_t *port_json)
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
		pr_err("Failed to parse JSON port dump.\n");
		return -EINVAL;
	}
	pr_out("%s\n", port_name);
	pr_out_indent_inc();
	pr_out2("ifindex: %d\n", ifindex);
	pr_out2("addr: %s\n", dev_addr);
	pr_out2("ethtool link: %dmbit/%sduplex/%s\n", speed, duplex,
						      boolupdown(up));
	err = stateview_json_port_link_watches_process(port_link_watches_json);
	if (err)
		goto err_out;
	err = stateview_json_port_runner_process(runner_name, port_json);
	pr_out_indent_dec();
err_out:
	return err;
}

static int stateview_json_ports_process(char *runner_name, json_t *dump_json)
{
	int err;
	json_t *ports_json;
	json_t *iter;

	err = json_unpack(dump_json, "{s:o}", "ports", &ports_json);
	if (err)
		return 0;
	pr_out("ports:\n");
	for (iter = json_object_iter(ports_json); iter;
	     iter = json_object_iter_next(ports_json, iter)) {
		const char *port_name = json_object_iter_key(iter);
		json_t *port_json = json_object_iter_value(iter);

		pr_out_indent_inc();
		err = stateview_json_port_process(runner_name, port_name,
						  port_json);
		if (err)
			return err;
		pr_out_indent_dec();
	}
	return 0;
}

static int stateview_json_runner_process(char *runner_name, json_t *json)
{
	int err;

	if (!strcmp(runner_name, "activebackup")) {
		char *active_port;

		pr_out("runner:\n");
		err = json_unpack(json, "{s:{s:s}}", "runner",
				  "active_port", &active_port);
		if (err) {
			pr_err("Failed to parse JSON runner dump.\n");
			return -EINVAL;
		}
		pr_out_indent_inc();
		pr_out("active port: %s\n", active_port);
		pr_out_indent_dec();
	} else if (!strcmp(runner_name, "lacp")) {
		int active;
		int sys_prio;
		int fast_rate;

		pr_out("runner:\n");
		err = json_unpack(json, "{s:{s:b, s:i, s:b}}", "runner",
				  "active", &active,
				  "sys_prio", &sys_prio,
				  "fast_rate", &fast_rate);
		if (err) {
			pr_err("Failed to parse JSON runner dump.\n");
			return -EINVAL;
		}
		pr_out_indent_inc();
		pr_out("active: %s\n", boolyesno(active));
		pr_out("fast rate: %s\n", boolyesno(fast_rate));
		pr_out2("system priority: %d\n", sys_prio);
		pr_out_indent_dec();
	}
	return 0;
}

static int stateview_json_process(char *dump)
{
	int err;
	char *runner_name;
	json_t *dump_json;

	err = __jsonload(&dump_json, dump);
	if (err)
		return err;
	err = stateview_json_setup_process(&runner_name, dump_json);
	if (err)
		goto free_json;
	err = stateview_json_ports_process(runner_name, dump_json);
	if (err)
		goto free_json;
	err = stateview_json_runner_process(runner_name, dump_json);
free_json:
	json_decref(dump_json);
	return err;
}

static int stateview_process_reply(char *reply)
{
	return stateview_json_process(reply);
}
/*
static int portconfigupdate_msg_prepare(const struct msg_ops *msg_ops,
					void *msg_ops_priv,
					int argc, char **argv, void *priv)
{
	return msg_ops->set_args(msg_ops_priv, "ss", argv[0], argv[1]);
}
*/

static int portconfigdump_json_process(char *dump, char *port_name)
{
	int err;
	json_t *json;
	json_t *port_json;
	json_t *ports_json;

	err = __jsonload(&json, dump);
	if (err)
		return err;
	err = json_unpack(json, "{s:o}", "ports", &ports_json);
	if (err) {
		pr_err("Failed to parse JSON dump.\n");
		err = -EINVAL;
		goto free_json;
	}
	err = json_unpack(ports_json, "{s:o}", port_name, &port_json);
	if (err) {
		pr_err("Port named \"%s\" not found.\n", port_name);
		err = -EINVAL;
		goto free_json;
	}
	err = __jsondump(port_json);
free_json:
	json_decref(json);
	return err;
}

static int call_method_config_jsonsimpledump(struct teamdctl *tdc,
					     int argc, char **argv)
{
	return jsonsimpledump_process_reply(teamdctl_config_get_raw(tdc));
}

static int call_method_config_jsonnoportsdump(struct teamdctl *tdc,
					      int argc, char **argv)
{
	return jsonnoportsdump_process_reply(teamdctl_config_get_raw(tdc));
}

static int call_method_config_actual_jsonsimpledump(struct teamdctl *tdc,
						    int argc, char **argv)
{
	return jsonsimpledump_process_reply(teamdctl_config_actual_get_raw(tdc));
}

static int call_method_state_jsonsimpledump(struct teamdctl *tdc,
					    int argc, char **argv)
{
	return jsonsimpledump_process_reply(teamdctl_state_get_raw(tdc));
}

static int call_method_state_stateview(struct teamdctl *tdc,
				       int argc, char **argv)
{
	return stateview_process_reply(teamdctl_state_get_raw(tdc));
}

static int call_method_port_add(struct teamdctl *tdc,
				int argc, char **argv)
{
	return teamdctl_port_add(tdc, argv[0]);
}

static int call_method_port_remove(struct teamdctl *tdc,
				   int argc, char **argv)
{
	return teamdctl_port_remove(tdc, argv[0]);
}

static int call_method_port_config_update(struct teamdctl *tdc,
					  int argc, char **argv)
{
	return teamdctl_port_config_update_raw(tdc, argv[0], argv[1]);
}

static int call_method_port_config_dump(struct teamdctl *tdc,
					int argc, char **argv)
{
	return portconfigdump_json_process(teamdctl_config_actual_get_raw(tdc),
					   argv[0]);
}

static int call_method_state_item_get(struct teamdctl *tdc,
				      int argc, char **argv)
{
	char *reply;
	int err;

	err = teamdctl_state_item_value_get(tdc, argv[0], &reply);
	if (err)
		return err;
	pr_out("%s\n", reply);
	free(reply);
	return 0;
}

static int call_method_state_item_set(struct teamdctl *tdc,
				      int argc, char **argv)
{
	return teamdctl_state_item_value_set(tdc, argv[0], argv[1]);
}


enum id_command_type {
	ID_CMDTYPE_NONE = 0,
	ID_CMDTYPE_C,
	ID_CMDTYPE_C_D,
	ID_CMDTYPE_C_D_N,
	ID_CMDTYPE_C_D_A,
	ID_CMDTYPE_S,
	ID_CMDTYPE_S_D,
	ID_CMDTYPE_S_V,
	ID_CMDTYPE_S_I,
	ID_CMDTYPE_S_I_G,
	ID_CMDTYPE_S_I_S,
	ID_CMDTYPE_P,
	ID_CMDTYPE_P_A,
	ID_CMDTYPE_P_R,
	ID_CMDTYPE_P_C,
	ID_CMDTYPE_P_C_U,
	ID_CMDTYPE_P_C_D,
};

typedef int (*process_reply_t)(int argc, char **argv, char *reply);
typedef int (*call_method_t)(struct teamdctl *tdc, int argc, char **argv);

#define COMMAND_PARAM_MAX_CNT 8

struct command_type {
	enum id_command_type id;
	enum id_command_type parent_id;
	char *name;
	char *params[COMMAND_PARAM_MAX_CNT];
	call_method_t call_method;
	process_reply_t process_reply;
	size_t priv_size;
};

static struct command_type command_types[] = {
	{
		.id = ID_CMDTYPE_C,
		.name = "config",
	},
	{
		.id = ID_CMDTYPE_C_D,
		.parent_id = ID_CMDTYPE_C,
		.name = "dump",
		.call_method = call_method_config_jsonsimpledump,
	},
	{
		.id = ID_CMDTYPE_C_D_N,
		.parent_id = ID_CMDTYPE_C_D,
		.name = "noports",
		.call_method = call_method_config_jsonnoportsdump,
	},
	{
		.id = ID_CMDTYPE_C_D_A,
		.parent_id = ID_CMDTYPE_C_D,
		.name = "actual",
		.call_method = call_method_config_actual_jsonsimpledump,
	},
	{
		.id = ID_CMDTYPE_S,
		.name = "state",
		.call_method = call_method_state_stateview,
	},
	{
		.id = ID_CMDTYPE_S_D,
		.parent_id = ID_CMDTYPE_S,
		.name = "dump",
		.call_method = call_method_state_jsonsimpledump,
	},
	{
		.id = ID_CMDTYPE_S_V,
		.parent_id = ID_CMDTYPE_S,
		.name = "view",
		.call_method = call_method_state_stateview,
	},
	{
		.id = ID_CMDTYPE_S_I,
		.parent_id = ID_CMDTYPE_S,
		.name = "item",
	},
	{
		.id = ID_CMDTYPE_S_I_G,
		.parent_id = ID_CMDTYPE_S_I,
		.name = "get",
		.call_method = call_method_state_item_get,
		.params = {"ITEMPATH"},
	},
	{
		.id = ID_CMDTYPE_S_I_S,
		.parent_id = ID_CMDTYPE_S_I,
		.name = "set",
		.call_method = call_method_state_item_set,
		.params = {"ITEMPATH", "VALUE"},
	},
	{
		.id = ID_CMDTYPE_P,
		.name = "port",
	},
	{
		.id = ID_CMDTYPE_P_A,
		.parent_id = ID_CMDTYPE_P,
		.name = "add",
		.call_method = call_method_port_add,
		.params = {"PORTDEV"},
	},
	{
		.id = ID_CMDTYPE_P_R,
		.parent_id = ID_CMDTYPE_P,
		.name = "remove",
		.call_method = call_method_port_remove,
		.params = {"PORTDEV"},
	},
	{
		.id = ID_CMDTYPE_P_C,
		.parent_id = ID_CMDTYPE_P,
		.name = "config",
	},
	{
		.id = ID_CMDTYPE_P_C_U,
		.parent_id = ID_CMDTYPE_P_C,
		.name = "update",
		.call_method = call_method_port_config_update,
		.params = {"PORTDEV", "PORTCONFIG"},
	},
	{
		.id = ID_CMDTYPE_P_C_D,
		.parent_id = ID_CMDTYPE_P_C,
		.name = "dump",
		.call_method = call_method_port_config_dump,
		.params = {"PORTDEV"},
	},
};

#define COMMAND_TYPE_COUNT ARRAY_SIZE(command_types)

static bool __cmd_executable(struct command_type *command_type)
{
	return command_type->call_method;
}

static int __cmd_param_cnt(struct command_type *command_type)
{
	int i = 0;

	while (command_type->params[i])
		i++;
	return i;
}

static struct command_type *__get_cmd_by_parent(char *cmd_name,
						enum id_command_type parent_id)
{
	int i;

	for (i = 0; i < COMMAND_TYPE_COUNT; i++) {
		if (!strncmp(command_types[i].name, cmd_name,
			     strlen(cmd_name)) &&
		    command_types[i].parent_id == parent_id)
			return &command_types[i];
	}
	return NULL;
}

static struct command_type *__get_cmd_by_id(enum id_command_type id)
{
	int i;

	for (i = 0; i < COMMAND_TYPE_COUNT; i++) {
		if (command_types[i].id == id)
			return &command_types[i];
	}
	return NULL;
}

static int find_command(struct command_type **pcommand_type,
			int *argc, char ***argv)
{
	char *cmd_name;
	enum id_command_type parent_id = ID_CMDTYPE_NONE;
	struct command_type *command_type;

	while (1) {
		if (!*argc) {
			pr_err("None or incomplete command\n");
			return -EINVAL;
		}
		cmd_name = *argv[0];
		(*argc)--;
		(*argv)++;
		command_type = __get_cmd_by_parent(cmd_name, parent_id);
		if (!command_type) {
			pr_err("Unknown command \"%s\".\n", cmd_name);
			return -EINVAL;
		}
		if (__cmd_executable(command_type) &&
		    __cmd_param_cnt(command_type) >= *argc) {
			*pcommand_type = command_type;
			return 0;
		}
		parent_id = command_type->id;
	}
}

static int check_command_params(struct command_type *command_type,
				int argc, char **argv)
{
	int i = 0;

	while (command_type->params[i]) {
		if (i == argc) {
			pr_err("Command line parameter \"%s\" expected.\n",
			       command_type->params[i]);
			return -EINVAL;
		}
		i++;
	}
	return 0;
}

static int check_team_devname(char *team_devname)
{
	int err;
	uint32_t ifindex = ifindex;

	err = ifname2ifindex(&ifindex, team_devname);
	if (err)
		return err;
	if (!ifindex) {
		pr_err("Device \"%s\" does not exist\n", team_devname);
		return -ENODEV;
	}
	return 0;
}

static int check_teamd_team_devname(struct teamdctl *tdc,
				    const char *team_devname)
{
	int ret = 0;
	json_t* root;
	json_error_t error;
	json_t* j_device_name;
	const char* teamd_device_name;

	root = json_loads(teamdctl_config_get_raw(tdc), 0, &error);
	j_device_name = json_object_get(root, "device");

	teamd_device_name = json_string_value(j_device_name);

	if (strcmp(team_devname, teamd_device_name) != 0) {
		pr_err("Unable to access to %s through connected teamd daemon because daemon controls %s.\n",
		       team_devname, teamd_device_name);
		ret = -1;
	}

	json_decref(j_device_name);
	json_decref(root);
	return ret;
}

static int call_command(struct teamdctl *tdc, int argc, char **argv,
			struct command_type *command_type)
{
	return command_type->call_method(tdc, argc, argv);
}

static void print_cmd(struct command_type *command_type)
{
	if (command_type->parent_id != ID_CMDTYPE_NONE) {
		print_cmd(__get_cmd_by_id(command_type->parent_id));
		pr_out(" ");
	}
	pr_out("%s", command_type->name);
}

static void print_help(const char *argv0) {
	int i, j;
	struct command_type *command_type;

	pr_out("%s [options] teamdevname command [command args]\n"
	       "    -h --help                Show this help\n"
	       "    -v --verbose             Increase output verbosity\n"
	       "    -o --oneline             Force output to one line if possible\n"
	       "    -D --force-dbus          Force to use D-Bus interface\n"
	       "    -Z --force-zmq=ADDRESS   Force to use ZeroMQ interface [-Z[Address]]\n"
	       "    -U --force-usock         Force to use UNIX domain socket interface\n",
	       argv0);
	pr_out("Commands:\n");
	for (i = 0; i < COMMAND_TYPE_COUNT; i++) {
		command_type = &command_types[i];
		if (!__cmd_executable(command_type))
			continue;
		pr_out("    ");
		print_cmd(command_type);
		for (j = 0; command_type->params[j]; j++)
			pr_out(" %s", command_type->params[j]);
		pr_out("\n");
	}
}

int main(int argc, char **argv)
{
	char *argv0 = argv[0];
	char *team_devname;
	static const struct option long_options[] = {
		{ "help",		no_argument,		NULL, 'h' },
		{ "verbose",		no_argument,		NULL, 'v' },
		{ "oneline",		no_argument,		NULL, 'o' },
		{ "force-dbus",		no_argument,		NULL, 'D' },
		{ "force-zmq",		required_argument,	NULL, 'Z' },
		{ "force-usock",	no_argument,		NULL, 'U' },
		{ NULL, 0, NULL, 0 }
	};
	int opt;
	int err;
	struct command_type *command_type;
	struct teamdctl *tdc;
	int ret;
	char *addr = NULL;
	bool force_dbus = false;
	bool force_zmq = false;
	bool force_usock = false;

	while ((opt = getopt_long(argc, argv, "hvoDZ:U",
				  long_options, NULL)) >= 0) {

		switch(opt) {
		case 'h':
			print_help(argv0);
			return EXIT_SUCCESS;
		case 'v':
			g_verbosity++;
			break;
		case 'o':
			g_oneline = true;
			break;
		case 'D':
#ifndef ENABLE_DBUS
			fprintf(stderr, "D-Bus support is not compiled-in\n");
			return EXIT_FAILURE;
#else
			force_dbus = true;
#endif
			break;
		case 'Z':
#ifndef ENABLE_ZMQ
			fprintf(stderr, "ZeroMQ support is not compiled-in\n");
			return EXIT_FAILURE;
#else
			force_zmq = true;
			addr = optarg;
#endif
			break;
		case 'U':
			force_usock = true;
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

	if ((force_usock && force_dbus) ||
	    (force_usock && force_zmq) ||
	    (force_dbus && force_zmq)) {
		pr_err("Only one interface could be forced at a time (UNIX domain socket, D-Bus, ZMQ).\n");
		print_help(argv0);
		return EXIT_FAILURE;
	}

	if (optind >= argc) {
		pr_err("No team device specified.\n");
		print_help(argv0);
		return EXIT_FAILURE;
	}
	argv += optind;
	team_devname = *argv++;
	argc -= optind + 1;

	err = find_command(&command_type, &argc, &argv);
	if (err) {
		print_help(argv0);
		return EXIT_FAILURE;
	}
	err = check_command_params(command_type, argc, argv);
	if (err) {
		print_help(argv0);
		return EXIT_FAILURE;
	}

	err = check_team_devname(team_devname);
	if (err)
		return EXIT_FAILURE;

	tdc = teamdctl_alloc();
	if (!tdc) {
		pr_err("teamdctl_alloc failed\n");
		return EXIT_FAILURE;
	}

	err = teamdctl_connect(tdc, team_devname, addr,
			       (force_usock ? "usock" : (force_dbus ?
			        "dbus": (force_zmq ? "zmq" :NULL))));
	if (err) {
		pr_err("teamdctl_connect failed (%s)\n", strerror(-err));
		ret = EXIT_FAILURE;
		goto teamdctl_free;
	}

	if (check_teamd_team_devname(tdc, team_devname)) {
		ret = EXIT_FAILURE;
		goto teamdctl_disconnect;
	}

	err = call_command(tdc, argc, argv, command_type);
	if (err) {
		pr_err("command call failed (%s)\n", strerror(-err));
		ret = EXIT_FAILURE;
		goto teamdctl_disconnect;
	}

	ret = EXIT_SUCCESS;

teamdctl_disconnect:
	teamdctl_disconnect(tdc);
teamdctl_free:
	teamdctl_free(tdc);
	return ret;
}
