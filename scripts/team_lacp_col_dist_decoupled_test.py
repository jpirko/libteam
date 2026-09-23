#! /usr/bin/env python3
"""
LACP collecting/distributing decoupling test (self-contained, needs root).

The col_dist_decoupled option decouples COLLECTING from DISTRIBUTING so an external control
plane can drive the data path (make-before-break):

  * the actor advertises COLLECTING only after the control plane confirms local
    ingress is programmed (the "latch": non-zero collecting_confirm), and
  * advertises DISTRIBUTING (and mirrors it into the kernel "enabled" flag) only
    once the latch is set AND the partner is collecting.

This suite brings real teamd instances up over veth pairs and drives them
through the decoupled collecting/distributing lifecycle. It is organised into scenarios, each of
which owns its topology.

   Copyright 2026 Nexthop Systems Inc. All rights reserved.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
"""

import sys
import os
import getopt
import json
import subprocess
import time

# LACP actor/partner state bit used to observe COLLECTING in a partner's view.
INFO_STATE_COLLECTING = 0x10

# Everything runs inside a private, uniquely named network namespace so the
# suite cannot touch (or tear down) host networking resources.
NETNS = "lacpdc%d" % os.getpid()


class CmdExecFailedException(Exception):
    def __init__(self, retval, cmd):
        self.retval = retval
        self.cmd = cmd

    def __str__(self):
        return "Command failed (%d): %s" % (self.retval, self.cmd)


def cmd_exec(cmd, cleaner=False, expect_fail=False):
    """Run a shell command inside the test netns and return stripped stdout.
    cleaner=True silences the echo and tolerates a non-zero exit (teardown).
    expect_fail=True asserts the command exits non-zero."""
    cmd = cmd.rstrip(" ")
    if not cmd.startswith("ip netns"):
        cmd = "ip netns exec %s %s" % (NETNS, cmd)
    if not cleaner:
        print("# \"%s\"" % cmd)
    subp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    (out, err) = subp.communicate()
    if expect_fail:
        assert subp.returncode != 0, \
            "expected non-zero exit, got success: %s" % cmd
    elif subp.returncode and not cleaner:
        if out:
            print(out)
        if err:
            print(err)
        raise CmdExecFailedException(subp.returncode, cmd)
    return out.rstrip()


def usage():
    print("Usage: team_lacp_col_dist_decoupled_test.py [OPTION...]")
    print("")
    print("  -h, --help                 print this message")
    sys.exit()


def wait_until(func, timeout=30, interval=0.5, description=""):
    """Poll func() -> (matched, detail) until matched, else raise with last detail."""
    deadline = time.time() + timeout
    detail = None
    while time.time() < deadline:
        (matched, detail) = func()
        if matched:
            return detail
        time.sleep(interval)
    raise AssertionError("timed out waiting for %s (last=%r)" % (description, detail))


class LacpColDistDecoupledTest:

    def __init__(self):
        # Scenario A: decoupled actor with a coupled partner.
        self.actor_team = "team_actor"
        self.actor_port = "veth_actor"
        self.partner_team = "team_partner"
        self.partner_port = "veth_partner"

        # Scenario B: two decoupled instances.
        self.team_a = "team_a"
        self.port_a = "veth_a"
        self.team_b = "team_b"
        self.port_b = "veth_b"

    # -----------------------------------------------------------------------
    # teamd / kernel plumbing
    # -----------------------------------------------------------------------

    def _build_config(self, team, port, decoupled, fast_rate=True):
        runner = {"name": "lacp", "active": True, "fast_rate": fast_rate, "min_ports": 1}
        if decoupled:
            runner["col_dist_decoupled"] = True
        return {"device": team, "runner": runner,
                "link_watch": {"name": "ethtool"}, "ports": {port: {}}}

    def _start_teamd(self, team, port, decoupled, fast_rate=True):
        config = json.dumps(self._build_config(team, port, decoupled,
                                               fast_rate))
        cmd_exec("teamd -c '%s' -d" % config)

    def _stop_teamd(self, team):
        cmd_exec("teamd -t %s -k" % team, cleaner=True)

    def _teamd_state_dump(self, team):
        return json.loads(cmd_exec("teamdctl %s state dump" % team, cleaner=True))

    def _runner(self, team, port):
        return self._teamd_state_dump(team)["ports"][port]["runner"]

    def _is_kernel_port_enabled(self, team, port):
        output = cmd_exec("teamnl -p %s %s getoption enabled" % (port, team),
                          cleaner=True)
        return output.strip().lower() in ("true", "1")

    def _is_carrier_up(self, team):
        return cmd_exec("cat /sys/class/net/%s/carrier" % team,
                        cleaner=True).strip() == "1"

    # -----------------------------------------------------------------------
    # Small predicates for wait_until(); each returns (matched, detail).
    # -----------------------------------------------------------------------

    def _port_field_is(self, team, port, field, expected):
        try:
            value = self._runner(team, port)[field]
            return (value == expected, value)
        except Exception as e:
            return (False, str(e))

    def _port_state_is_current(self, team, port):
        return self._port_field_is(team, port, "state", "current")

    def _confirm_epoch(self, team, port, epoch, expect_reject=False):
        # Echo an explicit request epoch back to teamd (0 withdraws collecting).
        # An accepted confirm must exit zero (cmd_exec raises otherwise); a
        # stale epoch must be rejected with a non-zero teamdctl exit status,
        # asserted via expect_fail.
        cmd_exec("teamdctl %s state item set ports.%s.runner.collecting_confirm %s" %
                 (team, port, epoch), cleaner=expect_reject,
                 expect_fail=expect_reject)

    def _set_collecting_confirmed(self, team, port, value):
        # The control-plane confirm is fenced by the request epoch: read the
        # current collecting_request_id and echo it back. Confirm 0
        # withdraws collecting.
        if value:
            epoch = self._runner(team, port)["collecting_request_id"]
            self._confirm_epoch(team, port, epoch)
        else:
            self._confirm_epoch(team, port, 0)

    def _confirmed_is(self, team, port, expected):
        # (matched, detail) predicate for wait_until: collecting is confirmed
        # iff collecting_confirm (the confirmed epoch) is non-zero.
        try:
            v = self._runner(team, port)["collecting_confirm"]
            return ((v != 0) == expected, "collecting_confirm=%r" % v)
        except Exception as e:
            return (False, str(e))

    # -----------------------------------------------------------------------
    # Topology setup / teardown
    # -----------------------------------------------------------------------

    def _setup_pair(self, port_a, port_b, team_a, team_b,
                    team_a_decoupled, team_b_decoupled):
        cmd_exec("ip link add %s type veth peer name %s" % (port_a, port_b))
        self._start_teamd(team_a, port_a, team_a_decoupled)
        self._start_teamd(team_b, port_b, team_b_decoupled)
        cmd_exec("ip link set %s up" % team_a)
        cmd_exec("ip link set %s up" % team_b)
        wait_until(lambda: self._port_state_is_current(team_a, port_a),
                   description="%s/%s reaching 'current'" % (team_a, port_a))
        wait_until(lambda: self._port_state_is_current(team_b, port_b),
                   description="%s/%s reaching 'current'" % (team_b, port_b))

    def _setup_scenario_a(self):
        self._setup_pair(self.actor_port, self.partner_port,
                         self.actor_team, self.partner_team,
                         team_a_decoupled=True, team_b_decoupled=False)

    def _setup_scenario_b(self):
        self._setup_pair(self.port_a, self.port_b, self.team_a, self.team_b,
                         team_a_decoupled=True, team_b_decoupled=True)

    def _cleanup(self):
        for team in (self.actor_team, self.partner_team,
                     self.team_a, self.team_b):
            self._stop_teamd(team)
        # deleting one end of each veth pair removes the whole pair
        for port in (self.actor_port, self.port_a):
            cmd_exec("ip link del %s" % port, cleaner=True)

    # =======================================================================
    # Scenario A: decoupled actor <-> coupled partner
    #
    # Walks the full make-before-break handshake: nothing forwards until the
    # control plane confirms collecting, distributing then follows the (coupled)
    # partner, and an own-link flap clears the latch until re-confirmed.
    # =======================================================================

    def _test_a_col_dist_decoupled_advertised(self):
        # Test: the runner reports collecting and distributing are decoupled.
        runner = self._teamd_state_dump(self.actor_team)["runner"]
        assert runner.get("col_dist_decoupled") is True, \
            "runner.col_dist_decoupled=%r" % runner.get("col_dist_decoupled")

    def _test_a_collecting_requested_by_default(self):
        # Test: once the port is up and synced, the actor *requests* collecting
        # (selected + agg-selected + partner in sync).
        wait_until(lambda: self._port_field_is(self.actor_team, self.actor_port,
                                               "collecting_requested", True),
                   description="collecting_requested becoming true")

    def _test_a_collecting_inactive_until_confirmed(self):
        # COLLECTING is not advertised until the control plane confirms.
        assert self._runner(self.actor_team, self.actor_port)["collecting"] is False, \
            "COLLECTING advertised before confirmation"

    def _test_a_kernel_disabled_before_confirm(self):
        # Kernel "enabled" is off before collecting is confirmed.
        assert not self._is_kernel_port_enabled(self.actor_team, self.actor_port), \
            "kernel port enabled before confirmation while decoupled"

    def _test_a_confirm_advertises_collecting(self):
        # Confirming makes the actor advertise COLLECTING, which the partner observes.
        self._set_collecting_confirmed(self.actor_team, self.actor_port, True)
        wait_until(lambda: (bool(self._runner(self.partner_team, self.partner_port)
                                 ["partner_lacpdu_info"]["state"] & INFO_STATE_COLLECTING),
                            None),
                   description="partner observing actor COLLECTING after confirm")

    def _test_a_distributing_follows_partner(self):
        # The coupled partner is already collecting, so once confirmed the actor
        # starts distributing.
        wait_until(lambda: self._port_field_is(self.actor_team, self.actor_port,
                                               "distributing", True),
                   description="actor distributing after confirm")

    def _test_a_kernel_enabled_after_distributing(self):
        # Test: kernel "enabled" mirrors distributing when decoupled.
        wait_until(lambda: (self._is_kernel_port_enabled(self.actor_team,
                                                         self.actor_port), None),
                   description="kernel port enabled after collecting/distributing")

    def _test_a_carrier_up_from_distributing(self):
        # Test: team carrier is driven by distributing ports, not merely synced
        # (kernel-enabled) ports.
        wait_until(lambda: (self._is_carrier_up(self.actor_team), None),
                   description="team carrier up from distributing")

    def _test_a_own_flap_clears_latch(self):
        # An own-link flap clears the latch and it stays cleared until the
        # control plane re-confirms (no COLLECTING/DISTRIBUTING on reselect).
        assert self._runner(self.actor_team, self.actor_port)["collecting_confirm"] != 0, \
            "expected latch set before flap"
        cmd_exec("ip link set %s down" % self.actor_port)
        wait_until(lambda: self._confirmed_is(self.actor_team, self.actor_port, False),
                   description="latch cleared on link down")
        cmd_exec("ip link set %s up" % self.actor_port)
        wait_until(lambda: self._port_field_is(self.actor_team, self.actor_port,
                                               "collecting_requested", True),
                   description="collecting requested again after link up")
        runner = self._runner(self.actor_team, self.actor_port)
        assert runner["collecting_confirm"] == 0, \
            "latch re-set on reselect without re-confirm (got %r)" % runner["collecting_confirm"]
        assert runner["collecting"] is False and runner["distributing"] is False, \
            "COLLECTING/DISTRIBUTING re-advertised after flap without re-confirm"

    def _test_a_deconfirm_clears_collecting(self):
        # Withdrawing the confirmation stops advertising COLLECTING.
        self._set_collecting_confirmed(self.actor_team, self.actor_port, True)
        wait_until(lambda: self._confirmed_is(self.actor_team, self.actor_port, True),
                   description="latch re-set before de-confirm")
        self._set_collecting_confirmed(self.actor_team, self.actor_port, False)
        wait_until(lambda: self._port_field_is(self.actor_team, self.actor_port,
                                               "collecting", False),
                   description="COLLECTING withdrawn after de-confirm")

    # =======================================================================
    # Scenario B: decoupled actor <-> decoupled partner
    #
    # With a decoupled partner, distributing must wait for the partner to
    # advertise collecting too.
    # =======================================================================

    def _test_b_distributing_off_without_partner(self):
        # Confirm our own collecting; distributing stays off because the
        # decoupled partner is not collecting.
        self._set_collecting_confirmed(self.team_a, self.port_a, True)
        wait_until(lambda: self._confirmed_is(self.team_a, self.port_a, True),
                   description="latch becoming true")
        assert self._runner(self.team_a, self.port_a)["distributing"] is False, \
            "distributing should be false while partner not collecting"

    def _test_b_distributing_on_with_partner(self):
        # Once the partner confirms collecting too, distributing turns on.
        self._set_collecting_confirmed(self.team_b, self.port_b, True)
        wait_until(lambda: self._port_field_is(self.team_a, self.port_a,
                                               "distributing", True),
                   description="distributing after partner collects")

    # =======================================================================
    # Scenario C: multi-member, single aggregator
    # =======================================================================

    def _test_c_member_flap_does_not_disturb_peer(self):
        # Test: flapping one member must not disturb the OTHER member's latch
        # or forwarding (agg_selected stays stable for the healthy member).
        tm, tp = "team_mm", "team_mmp"
        a1, a2, b1, b2 = "veth_mm1", "veth_mm2", "veth_mmb1", "veth_mmb2"
        M = json.dumps({"device": tm, "runner": {"name": "lacp", "active": True,
                        "fast_rate": True, "min_ports": 1, "col_dist_decoupled": True},
                        "link_watch": {"name": "ethtool"}, "ports": {a1: {}, a2: {}}})
        P = json.dumps({"device": tp, "runner": {"name": "lacp", "active": True,
                        "fast_rate": True, "min_ports": 1},
                        "link_watch": {"name": "ethtool"}, "ports": {b1: {}, b2: {}}})
        cmd_exec("ip link add %s type veth peer name %s" % (a1, b1))
        cmd_exec("ip link add %s type veth peer name %s" % (a2, b2))
        try:
            cmd_exec("teamd -c '%s' -d" % M)
            cmd_exec("teamd -c '%s' -d" % P)
            cmd_exec("ip link set %s up" % tm)
            cmd_exec("ip link set %s up" % tp)
            for p in (a1, a2):
                wait_until(lambda p=p: self._port_state_is_current(tm, p),
                           description="%s reaching 'current'" % p)
                self._set_collecting_confirmed(tm, p, True)
            for p in (a1, a2):
                wait_until(lambda p=p: self._port_field_is(tm, p, "distributing", True),
                           description="%s distributing" % p)
            # Flap member a2; member a1 must never lose collecting/distributing.
            cmd_exec("ip link set %s down" % a2)
            cmd_exec("ip link set %s up" % a2)
            for _ in range(6):
                r = self._runner(tm, a1)
                assert r["collecting_confirm"] != 0 and r["distributing"] is True, \
                    "peer member a1 disturbed by a2 flap: confirm=%r dist=%r" % \
                    (r["collecting_confirm"], r["distributing"])
                time.sleep(1)
        finally:
            self._stop_teamd(tm)
            self._stop_teamd(tp)
            cmd_exec("ip link del %s" % a1, cleaner=True)
            cmd_exec("ip link del %s" % a2, cleaner=True)

    # =======================================================================
    # Scenario D: request->confirm epoch fencing
    #
    # The control plane reads (collecting_requested, collecting_request_id),
    # programs ingress, then echoes the id back as the confirm. teamd advances
    # the request id whenever a new selection episode begins, and latches a
    # confirm only if its id matches the current one. A confirm carrying a
    # superseded (pre-flap) id must therefore be rejected, so a stale confirm
    # racing a link flap cannot re-enable forwarding for an episode whose
    # ingress is not programmed.
    # =======================================================================

    def _test_d_stale_confirm_rejected_by_epoch(self):
        tm, tp = "team_ep", "team_epp"
        a, b = "veth_ep", "veth_epp"
        M = json.dumps({"device": tm, "runner": {"name": "lacp", "active": True,
                        "fast_rate": True, "min_ports": 1, "col_dist_decoupled": True},
                        "link_watch": {"name": "ethtool"}, "ports": {a: {}}})
        P = json.dumps({"device": tp, "runner": {"name": "lacp", "active": True,
                        "fast_rate": True, "min_ports": 1},
                        "link_watch": {"name": "ethtool"}, "ports": {b: {}}})
        cmd_exec("ip link add %s type veth peer name %s" % (a, b))
        try:
            cmd_exec("teamd -c '%s' -d" % M)
            cmd_exec("teamd -c '%s' -d" % P)
            cmd_exec("ip link set %s up" % tm)
            cmd_exec("ip link set %s up" % tp)
            wait_until(lambda: self._port_state_is_current(tm, a),
                       description="member reaching 'current'")

            # Episode 1: confirm collecting so the member forwards, and capture
            # the epoch the control plane would have programmed for.
            wait_until(lambda: self._port_field_is(tm, a, "collecting_requested", True),
                       description="collecting requested (episode 1)")
            old_epoch = self._runner(tm, a)["collecting_request_id"]
            self._confirm_epoch(tm, a, old_epoch)
            wait_until(lambda: self._port_field_is(tm, a, "distributing", True),
                       description="member forwarding in episode 1")

            # Own-link flap: clears the latch and begins a new selection episode.
            cmd_exec("ip link set %s down" % a)
            wait_until(lambda: self._port_field_is(tm, a, "collecting_requested", False),
                       description="collecting request cleared on link down")
            cmd_exec("ip link set %s up" % a)
            wait_until(lambda: self._port_field_is(tm, a, "collecting_requested", True),
                       description="collecting requested again (episode 2)")
            new_epoch = self._runner(tm, a)["collecting_request_id"]
            assert new_epoch > old_epoch, \
                "request epoch must advance across a flap (old=%r new=%r)" % \
                (old_epoch, new_epoch)

            # A confirm carrying the stale (episode-1) epoch must be rejected:
            # teamdctl fails and the latch stays clear.
            self._confirm_epoch(tm, a, old_epoch, expect_reject=True)
            runner = self._runner(tm, a)
            assert runner["collecting_confirm"] == 0, \
                "stale confirm (old epoch) must not latch collecting (got %r)" % \
                runner["collecting_confirm"]
            assert runner["distributing"] is False, \
                "stale confirm must not enable distributing"

            # A confirm with the current epoch is honored.
            self._confirm_epoch(tm, a, new_epoch)
            wait_until(lambda: self._port_field_is(tm, a, "distributing", True),
                       description="member forwards after fresh (current-epoch) confirm")
        finally:
            self._stop_teamd(tm)
            self._stop_teamd(tp)
            cmd_exec("ip link del %s" % a, cleaner=True)

    # =======================================================================
    # Runner
    # =======================================================================


    # =======================================================================
    # Scenario E: aggregator switch refreshes decoupled state
    #
    # The selected aggregator is input to the decoupled collecting decision;
    # switching aggregators (with no event on the deselected port itself)
    # must refresh every port's requested state and epoch, so a confirmation
    # computed before the switch is rejected after it.
    # =======================================================================

    def _test_e_agg_switch_rejects_racing_confirm(self):
        td, tpa, tpb = "team_dut", "team_pa", "team_pb"
        d1, d2, d3 = "veth_d1", "veth_d2", "veth_d3"
        pa1, pb1, pb2 = "veth_pa1", "veth_pb1", "veth_pb2"
        # Slow LACP rate on purpose: periodic PDUs (each of which refreshes
        # the receiving port's actor state) are 30s apart, so between the
        # aggregator switch and the racing confirm below there is no
        # spontaneous refresh on d1 -- only the switch itself may provide it.
        D = json.dumps({"device": td, "runner": {"name": "lacp", "active": True,
                        "min_ports": 1, "col_dist_decoupled": True,
                        "agg_select_policy": "count"},
                        "link_watch": {"name": "ethtool"},
                        "ports": {d1: {}, d2: {}, d3: {}}})
        A = json.dumps({"device": tpa, "runner": {"name": "lacp", "active": True,
                        "min_ports": 1},
                        "link_watch": {"name": "ethtool"}, "ports": {pa1: {}}})
        B = json.dumps({"device": tpb, "runner": {"name": "lacp", "active": True,
                        "min_ports": 1},
                        "link_watch": {"name": "ethtool"}, "ports": {pb1: {}, pb2: {}}})

        def agg_selected(port):
            agg = self._runner(td, port).get("aggregator", {})
            return (bool(agg.get("selected")), agg)

        cmd_exec("ip link add %s type veth peer name %s" % (d1, pa1))
        cmd_exec("ip link add %s type veth peer name %s" % (d2, pb1))
        cmd_exec("ip link add %s type veth peer name %s" % (d3, pb2))
        try:
            cmd_exec("teamd -c '%s' -d" % D)
            cmd_exec("teamd -c '%s' -d" % A)
            cmd_exec("teamd -c '%s' -d" % B)
            # Keep the two-port aggregator {d2,d3} down: the single-port
            # aggregator {d1} is the only candidate and gets selected.
            cmd_exec("ip link set %s down" % d2)
            cmd_exec("ip link set %s down" % d3)
            cmd_exec("ip link set %s up" % td)
            cmd_exec("ip link set %s up" % tpa)
            cmd_exec("ip link set %s up" % tpb)
            wait_until(lambda: agg_selected(d1),
                       description="aggregator {d1} selected")
            wait_until(lambda: self._port_field_is(td, d1,
                                                   "collecting_requested", True),
                       description="d1 requesting collecting")
            stale_epoch = self._runner(td, d1)["collecting_request_id"]

            # Bring the second aggregator up: with the "count" policy the
            # selection switches to {d2,d3} while d1's own link never flaps.
            cmd_exec("ip link set %s up" % d2)
            cmd_exec("ip link set %s up" % d3)
            wait_until(lambda: agg_selected(d2),
                       description="selection switching to two-port agg")

            # A confirmation computed for the pre-switch epoch loses the race:
            # teamd must reject it (non-zero teamdctl exit) and stay
            # unlatched. Fired immediately after the switch: only the
            # switch-time refresh can have withdrawn d1's cached request.
            self._confirm_epoch(td, d1, stale_epoch, expect_reject=True)

            # The switch alone (no event on d1) must have refreshed d1.
            matched, detail = self._port_field_is(td, d1,
                                                  "collecting_requested", False)
            assert matched, "d1 still requesting after switch: %r" % detail
            matched, detail = self._confirmed_is(td, d1, False)
            assert matched, "stale confirm latched: %s" % detail
            matched, detail = self._port_field_is(td, d1, "collecting", False)
            assert matched, "d1 advertising COLLECTING: %r" % detail
            assert not self._is_kernel_port_enabled(td, d1), \
                "kernel port d1 enabled after rejected stale confirm"

            # The freshly selected aggregator works normally end-to-end.
            self._set_collecting_confirmed(td, d2, True)
            wait_until(lambda: self._port_field_is(td, d2, "collecting", True),
                       description="d2 collecting after fresh confirm")
        finally:
            for team in (td, tpa, tpb):
                self._stop_teamd(team)
            for port in (d1, d2, d3):
                cmd_exec("ip link del %s" % port, cleaner=True)

    def _scenarios(self):
        return [
            ("Scenario A: decoupled actor <-> coupled partner",
             self._setup_scenario_a, [
                ("col_dist_decoupled advertised",        self._test_a_col_dist_decoupled_advertised),
                ("collecting requested by default",      self._test_a_collecting_requested_by_default),
                ("collecting inactive until confirmed",  self._test_a_collecting_inactive_until_confirmed),
                ("kernel disabled before confirm",       self._test_a_kernel_disabled_before_confirm),
                ("confirm advertises COLLECTING",        self._test_a_confirm_advertises_collecting),
                ("distributing follows partner",         self._test_a_distributing_follows_partner),
                ("kernel enabled after distributing",    self._test_a_kernel_enabled_after_distributing),
                ("carrier up from distributing",         self._test_a_carrier_up_from_distributing),
                ("own-link flap clears latch",           self._test_a_own_flap_clears_latch),
                ("de-confirm clears COLLECTING",         self._test_a_deconfirm_clears_collecting),
             ]),
            ("Scenario B: decoupled actor <-> decoupled partner",
             self._setup_scenario_b, [
                ("distributing off without partner",     self._test_b_distributing_off_without_partner),
                ("distributing on with partner",         self._test_b_distributing_on_with_partner),
             ]),
            ("Scenario C: multi-member, single aggregator",
             None, [
                ("member flap does not disturb peer",    self._test_c_member_flap_does_not_disturb_peer),
             ]),
            ("Scenario D: request->confirm epoch fencing",
             None, [
                ("stale confirm rejected by epoch",      self._test_d_stale_confirm_rejected_by_epoch),
             ]),
            ("Scenario E: aggregator switch refreshes decoupled state",
             None, [
                ("agg switch rejects racing confirm",    self._test_e_agg_switch_rejects_racing_confirm),
             ]),
        ]

    def _run_testlet(self, name, testlet, failures):
        print("--- Test: %s" % name)
        try:
            testlet()
            print("    PASS")
        except Exception as e:
            print("    FAIL: %s" % e)
            failures.append(name)

    def run(self):
        failures = []
        cmd_exec("ip netns add %s" % NETNS)
        try:
            for banner, setup, testlets in self._scenarios():
                print("")
                print("=== %s ===" % banner)
                if setup:
                    setup()
                for name, testlet in testlets:
                    self._run_testlet(name, testlet, failures)
        finally:
            self._cleanup()
            cmd_exec("ip netns del %s" % NETNS, cleaner=True)

        print("")
        if failures:
            raise AssertionError("LACP col_dist_decoupled test FAILED (%d): %s" %
                                 (len(failures), ", ".join(failures)))
        print("ALL LACP COL_DIST_DECOUPLED TESTS PASSED")


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
    LacpColDistDecoupledTest().run()


if __name__ == "__main__":
    main()
