# Copyright (c) 2026 Solutions-Innovation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

"""EVPN cross-cluster dataplane handler for the BGPVPN OVS agent extension.

Background
----------
Upstream :mod:`networking_bagpipe.bagpipe_bgp.vpn.evpn.ovs` defines
``OVSEVIDataplane`` and ``OVSDataplaneDriver``: a per-EVI dataplane that
installs OpenFlow rules on ``br-tun`` for cross-PE EVPN.  The upstream driver
is constructed by the standalone ``bagpipe-bgp`` daemon and instantiates
``br_tun.OVSTunnelBridge(..., os_ken_app=self)`` where ``self`` is the
``OVSDataplaneDriver`` object - which is *not* an os-ken application, has no
OpenFlow listener at ``127.0.0.1:6633``, and lacks ``send_request()``.  The
first ``add_flow`` call therefore raises ``AttributeError``.

Note: standalone ``bagpipe-bgp`` *can* still create OVS *ports* via OVSDB
(``ovs-vsctl add-port``); it is only OpenFlow flow installation that needs
the controller context.  In a partially-deployed cluster you may see
per-PE ``vxlan-XXXXXX`` ports already on ``br-tun`` even though no flows
target them - that is bagpipe-bgp having succeeded at OVSDB and failed at
OF.  Our handler is idempotent against pre-existing ports
(``OVSTunnelBridge.add_tunnel_port`` returns the existing ofport).

OpenFlow connection direction is switch-initiated (``ovs-vswitchd``
connects out to the controller's ``:6633`` listener).  Only the listener
owner has an established session it can ``send_msg`` over.  The agent's
``neutron-openvswitch-agent`` Python process *is* that controller (via its
embedded ``os-ken`` ``RyuApp``); a separate ``bagpipe-bgp`` Linux process
on the same host - even with ``hostNetwork=true`` - cannot share that
session because the ``Datapath`` object lives in the agent's interpreter.

This module fixes the gap by re-implementing the same flow-construction
logic as ``OVSEVIDataplane`` *inside* the ``bagpipe_bgpvpn`` agent
extension, where ``self.tun_br`` is the agent's working
``OVSTunnelBridge`` instance with a real os-ken context.  We do not modify
``bagpipe-bgp`` standalone; operators must set
``[DATAPLANE_DRIVER_EVPN] dataplane_driver = dummy`` so the daemon does
not try (and fail) to program OVS itself.

Mechanism
---------
* The agent extension instantiates :class:`EvpnXcHandler` at the end of
  :meth:`BagpipeBgpvpnAgentExtension.initialize`.
* The handler runs an :class:`oslo_service.loopingcall.FixedIntervalLoopingCall`
  that polls bagpipe-bgp's looking-glass REST at
  ``http://<host>:<port>/looking-glass/vpns/instances/<EVI>/best_routes``
  for current EVPN routes.  bagpipe-bgp 22.0.0 emits routes as a JSON
  object whose **outer keys are tuples of (route-type, identifier)**
  (e.g. ``"('MAC', FA:16:3E:35:F1:0B)"``) and whose values are lists of
  dicts whose **single inner key is an NLRI string**.  We parse both.
* Type-2 routes (MAC/IP) become ``UCAST_TO_TUN`` flows plus ARP responder
  entries on ``br-tun``.  Type-3 (IMET) routes become flooding bucket
  entries on the EVI's group.  Per-MAC unicast targets a per-PE VXLAN
  port on ``br-tun`` managed by :class:`PerPeVxlanPortMgr`.
* Flow-installation primitives are the agent's ``self.tun_br`` (already
  an ``OVSTunnelBridge``), wrapped with
  :class:`networking_bagpipe.bagpipe_bgp.common.dataplane_utils.OVSBridgeWithGroups`
  so we can use the same ``mod_group`` / ``add_group`` / ``delete_group``
  helpers ``OVSEVIDataplane`` uses.
* All fork-installed flows carry cookie :data:`COOKIE` for clean rollback
  via ``ovs-ofctl del-flows br-tun cookie=0xbac10e07/-1``.

State for each EVI is a :class:`EviState` object held in
``EvpnXcHandler.evis``.  An EVI is keyed by its ``vpn_instance_id`` (the
bagpipe-bgp instance identifier, typically ``evpn_<network-uuid>``).

Phase
-----
This is a Phase-1 implementation: polling, per-port VTEP, no graceful agent
restart resync of remote MAC mobility.  Functional Linux tests are out of
scope for the first commit; see ``test_evpn_xc_handler.py`` for the unit
tests landed alongside the agent_extension hook.

Schema reference (bagpipe-bgp 22.0.0)
-------------------------------------
Type-2 (MAC/IP) inner-key format::

    evpn:macadv::<rd_pe>:<eth_tag>:<esi>:<eth_tag2>:<MAC>/<masklen>:<IP>: label <label> (<vni>)

Example::

    evpn:macadv::172.16.85.53:0:-:0:FA:16:3E:B5:FE:D2/48:10.99.0.11: label 624 (9999)

Type-3 (Inclusive Multicast) inner-key format::

    evpn:multicast::<rd_pe>:<eth_tag>:<eth_tag2>:<originator_ip>

Example::

    evpn:multicast::172.16.85.53:0:0:172.16.85.53

For Type-3 the VNI lives in ``attributes.pmsi-tunnel``::

    pmsi:ingressreplication:0:<label>(<vni>):<originator_ip>

References
----------
* :mod:`networking_bagpipe.bagpipe_bgp.vpn.evpn.ovs` - the upstream EVPN
  OVS dataplane driver this module replaces in standalone bagpipe-bgp.
* ``doc/cluster53-54/20260529_bgpvpn_cross_cluster_53_54_v2.md`` (in the
  Solutions-Innovation overlay-networking-wrcp repo) - operator deploy
  recipe and validation runbook.
"""

import collections
import configparser
import ipaddress
import os
import re
import threading

import requests

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_service import loopingcall

from networking_bagpipe._i18n import _
from networking_bagpipe.bagpipe_bgp.common import dataplane_utils

from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent

from neutron_lib import constants as n_consts
from neutron_lib.plugins.ml2 import ovs_constants as ovs_const


LOG = logging.getLogger(__name__)


# Cookie used on every flow this module installs.
# 0xbac10e07 (10 hex digits = 40 bits, fits in a 64-bit cookie):
#   "bag1pe-xc" mnemonic - distinguishes Solutions-Innovation fork flows
#   from upstream agent extension static flows and from l2pop dynamic flows
#   on the same br-tun.
COOKIE = 0xbac10e07

# Phase-2 cookie for Type-5 inter-subnet routing flows.
# Independent lifecycle from Phase-1 cookie for clean per-phase rollback:
#   ovs-ofctl del-flows br-tun cookie=0xbac10e57/-1  (Type-5 only)
#   ovs-ofctl del-flows br-tun cookie=0xbac10e07/-1  (Type-2/3 only)
COOKIE_T5 = 0xbac10e57

# Priority of UCAST_TO_TUN, ARP responder, FLOOD_TO_TUN entries we install.
# Same priority upstream OVSEVIDataplane uses, so behaviour is comparable.
FLOW_PRIORITY = 5

# Phase-2: new OVS table for VRF-scoped L3 re-bridge after L3VNI decap.
# Table 50 is unused by neutron's standard pipeline (tables 0-22 + 60-63).
XC_L3_ROUTE_TABLE = 50

# Sentinel for "the local PE itself".  When a Type-3 IMET route advertises
# the local VTEP we record it as "local" and exclude it from BUM head-end
# replication (the local agent already delivers via patch-tun).
_LOCAL_PORT_SENTINEL = "local"


# --- bagpipe-bgp 22.0.0 inner-key NLRI parsers ---------------------------
#
# bagpipe-bgp does not give us structured fields for the route NLRI; instead
# the JSON object has an "inner key" string whose contents encode the NLRI.
# Parse that string back into useful fields.  Regex chosen for readability,
# not performance - we run this at most once per route per poll cycle.

# Type-2 macadv: evpn:macadv::<rd_pe>:<a>:<b>:<c>:<MAC>/<masklen>:<IP>: label <label> (<vni>)
# Example     : evpn:macadv::172.16.85.53:0:-:0:FA:16:3E:B5:FE:D2/48:10.99.0.11: label 624 (9999)
_RE_T2 = re.compile(
    r'^evpn:macadv::'
    r'(?P<rd_pe>[^:]+):'           # RD originator IP
    r'[^:]*:'                      # eth_tag
    r'[^:]*:'                      # esi
    r'[^:]*:'                      # eth_tag2
    r'(?P<mac>[0-9A-Fa-f:]{17})/[0-9]+'   # MAC/48
    r'(?::(?P<ip>[0-9.]+|[0-9A-Fa-f:]+))?'  # optional :IP
    r':\s*label\s+\d+\s+\((?P<vni>\d+)\)'  # : label N (VNI)
    r'\s*$',
)

# Type-3 multicast: evpn:multicast::<rd_pe>:<a>:<b>:<originator_ip>
_RE_T3 = re.compile(
    r'^evpn:multicast::'
    r'(?P<rd_pe>[^:]+):'
    r'[^:]*:'                      # eth_tag
    r'[^:]*:'                      # eth_tag2
    r'(?P<originator>[0-9.]+|[0-9A-Fa-f:]+)\s*$'
)

# pmsi-tunnel: pmsi:ingressreplication:<x>:<label>(<vni>):<originator_ip>
_RE_PMSI = re.compile(
    r'\((?P<vni>\d+)\)'
)

# --- Phase-2: Type-5 IP Prefix route (inter-subnet routing) ---------------
#
# exabgp 4.2.22 repr() format for EVPN Prefix NLRI (SHORT_NAME="PrfxAdv"):
#   evpn:prfxadv::<rd_ip>:<rd_port>:<esi>:<etag>:<prefix>/<masklen>:<gwip>: label <raw> (<l3vni>)
# Example (VNI=1000, VXLAN encoding raw=vni>>4):
#   evpn:prfxadv::172.16.85.54:0:-:0:10.98.0.0/24:0.0.0.0: label 62 (1000)
#
# NOTE: The prefix token is "evpn:prfxadv::" NOT "evpn:prefix::".
#       ESI field is "-" for zero ESI; gwip is "0.0.0.0".
#       L3VNI is extracted from the parenthesized value after "label <raw>".
_RE_T5 = re.compile(
    r'^evpn:prfxadv::'          # SHORT_NAME="PrfxAdv" in exabgp prefix.py
    r'(?P<rd_pe>[^:]+):'        # RD IP (e.g. "172.16.85.54")
    r'[^:]*:'                   # RD port (e.g. "0")
    r'[^:]*:'                   # ESI (typically "-" for empty)
    r'[^:]*:'                   # etag (e.g. "0")
    r'(?P<prefix>[0-9.]+/\d+)' # IP prefix/masklen (e.g. "10.98.0.0/24")
    r':[^:]*'                   # gwip (e.g. "0.0.0.0")
    r':\s*label\s+\d+\s+\((?P<l3vni>\d+)\)'  # label; l3vni in parens
    r'\s*$',
)


# Router MAC extended community (carried in Type-5 route attributes)
_RE_RMAC = re.compile(r'rmac:(?P<mac>[0-9A-Fa-f:]{17})')


# Config group dedicated to this handler so it does not pollute upstream
# [BAGPIPE].  Operators set these in the same neutron config file the OVS
# agent reads (the helm-rendered ml2_conf.ini, which already includes a
# [BAGPIPE] section from upstream).
xc_opts = [
    cfg.StrOpt('xc_bagpipe_api_host',
               default='127.0.0.1',
               help=_("Hostname or IP of the bagpipe-bgp REST API "
                      "(looking-glass) used by EvpnXcHandler.  bagpipe-bgp "
                      "runs on the same host as the OVS agent and listens "
                      "on loopback by default.")),
    cfg.IntOpt('xc_bagpipe_api_port',
               default=8082,
               min=1, max=65535,
               help=_("Port of the bagpipe-bgp REST API.")),
    cfg.IntOpt('xc_poll_interval',
               default=5,
               min=1,
               help=_("How often (seconds) to poll bagpipe-bgp's "
                      "looking-glass for new EVPN routes.  Lower values "
                      "shorten convergence; higher values reduce load.")),
    cfg.StrOpt('xc_local_ip',
               default=None,
               help=_("Local underlay IP used as VXLAN source for "
                      "cross-cluster traffic.  Distinct from the OVS "
                      "agent's intra-cluster local_ip - intra-cluster "
                      "VXLAN egresses on enp160s0f0 (data0), cross-cluster "
                      "egresses on enp160s0f1 (data1).  Must equal "
                      "[BGP] local_address in /etc/bagpipe-bgp/bgp.conf.  "
                      "If unset, the handler refuses to start.")),
    cfg.IntOpt('xc_request_timeout',
               default=2,
               min=1,
               help=_("HTTP timeout (seconds) for bagpipe-bgp REST calls.")),
    # Phase-2 optional overrides (normally auto-resolved from looking-glass)
    cfg.StrOpt('xc_local_router_mac',
               default=None,
               help=_("Override for the local router MAC (rmac) used in "
                      "Phase-2 Type-5 inter-subnet routing.  Normally "
                      "resolved from the bagpipe-bgp looking-glass "
                      "(local IPVPN route's rmac: extended community).  "
                      "Set this only if looking-glass resolution fails.")),
    cfg.IntOpt('xc_l3vni',
               default=None,
               help=_("Override for the L3VNI used in Phase-2 Type-5 "
                      "routing.  Normally auto-derived from the Type-5 "
                      "route's NLRI label field.  Set only if label "
                      "parsing produces incorrect values.")),
]

# Group name in cfg - kept under [BAGPIPE_XC] to leave [BAGPIPE] alone.
CONF_GROUP = 'BAGPIPE_XC'
cfg.CONF.register_opts(xc_opts, CONF_GROUP)


def _reload_bagpipe_xc_opts():
    """Re-read [BAGPIPE_XC] from the agent's --config-file list at import time.

    The neutron-openvswitch-agent parses its config files at process startup,
    BEFORE the bagpipe_bgpvpn extension module is imported.  Because this
    module registers the [BAGPIPE_XC] opts at import time (just above),
    oslo-config has already silently discarded the [BAGPIPE_XC] section by
    the time the opts are registered -- so cfg.CONF.BAGPIPE_XC.* read their
    defaults (e.g. xc_local_ip=None) instead of the operator-set values,
    and EvpnXcHandler.__init__ raises ValueError, disabling the poll-based
    reconciler that re-installs cross-cluster flows after an agent bounce.

    This re-reads [BAGPIPE_XC] from the same --config-file paths the agent
    used (discovered from /proc/self/cmdline) and set_override()s each value
    so the reconciler can actually start.  Safe no-op if /proc/self/cmdline
    is unavailable (e.g. unit-test import) or [BAGPIPE_XC] is absent.

    Every branch logs so a future misconfiguration can be pinpointed from the
    agent log alone (no in-pod python needed):
      - which --config-file paths were discovered from /proc/self/cmdline
      - which of those were readable vs missing
      - whether [BAGPIPE_XC] was found, and in which file
      - each opt overridden (name, coerced value, type) or skipped (reason)
      - the final resolved xc_local_ip that EvpnXcHandler.__init__ will see
    """
    try:
        with open('/proc/self/cmdline', 'rb') as f:
            argv = [a.decode() for a in f.read().split(b'\x00') if a]
    except Exception as exc:
        # /proc/self/cmdline unavailable (e.g. unit-test import, non-Linux).
        # Not fatal: opts keep their defaults; handler will disable itself
        # with the usual 'BAGPIPE_XC.xc_local_ip is not configured' message.
        LOG.info("xc: config-reload: cannot read /proc/self/cmdline (%s); "
                 "[BAGPIPE_XC] will use oslo-registered defaults", exc)
        return
    files = []
    for i, a in enumerate(argv):
        if a == '--config-file' and i + 1 < len(argv):
            files.append(argv[i + 1])
        elif a.startswith('--config-file='):
            files.append(a.split('=', 1)[1])
    if not files:
        LOG.debug("xc: config-reload: no --config-file in /proc/self/cmdline "
                  "(argv=%s); skipping re-read", argv[:1])
        return
    readable = [f for f in files if f and os.path.exists(f)]
    missing = [f for f in files if not (f and os.path.exists(f))]
    LOG.info("xc: config-reload: discovered %d --config-file path(s): %s",
             len(files), files)
    if missing:
        LOG.warning("xc: config-reload: %d path(s) not readable, skipping "
                    "them: %s", len(missing), missing)
    # interpolation=None: [DEFAULT] keys like log_format='[%(name)s] %(message)s'
    # would otherwise raise InterpolationMissingOptionError during cp.items().
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(readable)
    if not cp.has_section(CONF_GROUP):
        LOG.warning("xc: config-reload: no [%s] section in any of %s; "
                    "EvpnXcHandler will disable itself (xc_local_ip stays "
                    "None). Operator fix: add [%s] xc_local_ip=<underlay-ip> "
                    "to the agent's ml2_conf.ini.",
                    CONF_GROUP, readable, CONF_GROUP)
        return
    # Find which file actually contributed the section (for log attribution).
    source_file = None
    for f in readable:
        per_file = configparser.ConfigParser(interpolation=None)
        per_file.read(f)
        if per_file.has_section(CONF_GROUP):
            source_file = f
            break
    LOG.info("xc: config-reload: [%s] found in %s; applying overrides",
             CONF_GROUP, source_file or readable[0])
    opt_by_name = {o.name: o for o in xc_opts}
    applied = 0
    skipped = []
    for key, val in cp.items(CONF_GROUP):
        opt = opt_by_name.get(key)
        if opt is None:
            # Unknown key in [BAGPIPE_XC] (typo, or a future opt not in this
            # build). Not fatal; record so a typo is visible in the log.
            skipped.append("%s (not a registered XC opt)" % key)
            continue
        try:
            coerced = int(val) if isinstance(opt, cfg.IntOpt) else val
            cfg.CONF.set_override(key, coerced, CONF_GROUP)
            LOG.debug("xc: config-reload: override %s=%r (%s)",
                      key, coerced, type(coerced).__name__)
            applied += 1
        except ValueError:
            skipped.append("%s=%r (invalid %s)" % (key, val, type(opt).__name__))
        except KeyError as exc:
            skipped.append("%s=%r (KeyError: %s)" % (key, val, exc))
        except Exception as exc:
            # set_override can raise oslo-internal errors (e.g. already
            # overridden); keep the agent alive and log for diagnosis.
            skipped.append("%s=%r (%s: %s)" % (key, val, type(exc).__name__, exc))
    final_ip = cfg.CONF.BAGPIPE_XC.xc_local_ip
    LOG.info("xc: config-reload: applied %d override(s), skipped %d; "
             "xc_local_ip now=%r%s%s",
             applied, len(skipped), final_ip,
             "; skipped=" + ",".join(skipped) if skipped else "",
             "" if final_ip is not None else
             " (STILL None -> EvpnXcHandler will disable itself)")


_reload_bagpipe_xc_opts()


class EviState:
    """Per-EVI bookkeeping for a single VPN instance.

    Indexed by ``vpn_instance_id`` (the bagpipe-bgp instance ID, e.g.
    ``"evpn_<network-uuid>"``).  Tracks which Type-2 (MAC/IP) and Type-3
    (BUM/IMET) routes have been turned into flows so the next poll cycle
    can compute a diff and install/remove only what changed.

    Holds:

    * ``vlan`` - the local VLAN tag on br-tun for this EVI's network.
      Provisioned by the OVS agent when the first port on the network came
      up; we read it from ``vlan_manager`` lazily.
    * ``vni`` - the VNI carried on the wire.  For VXLAN tenant networks
      bagpipe reuses the Neutron network's segmentation_id; for non-VXLAN
      tenant networks the VNI comes from the BGPVPN's ``vni`` attribute.
    * ``local_pe`` - the local underlay IP advertised in BGP routes
      originated by this host's bagpipe-bgp (= ``CONF.BAGPIPE_XC.xc_local_ip``).
    * ``unicast`` - dict ``mac -> (ip, remote_pe, ofport)``.  Tracks installed
      Type-2-derived flows.
    * ``flooding`` - dict ``remote_pe -> ofport``.  Tracks installed Type-3
      flooding-bucket entries.  ``ofport`` is the per-PE tunnel port on
      br-tun managed by :class:`PerPeVxlanPortMgr`; ``"local"`` is used
      when the route originates locally.
    """

    __slots__ = ("vpn_instance_id", "vlan", "vni", "local_pe",
                 "unicast", "flooding")

    def __init__(self, vpn_instance_id):
        self.vpn_instance_id = vpn_instance_id
        self.vlan = None
        self.vni = None
        self.local_pe = None
        self.unicast = {}
        self.flooding = {}

    def __repr__(self):
        return ("EviState(id=%s, vlan=%s, vni=%s, "
                "n_unicast=%d, n_flooding=%d)" %
                (self.vpn_instance_id, self.vlan, self.vni,
                 len(self.unicast), len(self.flooding)))


class IpvpnEviState:
    """Per-L3VPN instance state for cross-cluster IP prefix (Type-5) routing.

    Tracks the dataplane state for one IPVPN instance (one router association).
    Each instance maps to a unique L3VNI and VRF on the wire.

    Holds:

    * ``vpn_instance_id`` - e.g. ``"ipvpn_<router-uuid>"``.
    * ``l3vni`` - the L3 VNI carried on the wire for this VRF (from Type-5
      NLRI label field).
    * ``local_router_mac`` - the local rmac (from bagpipe-bgp looking-glass
      or config override), used as dl_dst match in egress flows.
    * ``prefixes`` - dict ``prefix_str -> (remote_pe, remote_router_mac,
      ofport)``.  Tracks installed Type-5-derived egress flows.
    * ``l2_vlans`` - set of local OVS VLANs that belong to this L3VPN's
      subnets (used for installing per-VLAN egress flows).
    * ``local_subnets`` - set of locally-attached subnet CIDRs.  Used by
      ``_is_local_prefix()`` guardrail.
    * ``vrf_id`` - locally-significant integer loaded into reg0 for table 50
      VRF isolation.
    """

    __slots__ = ("vpn_instance_id", "l3vni", "local_router_mac",
                 "prefixes", "l2_vlans", "local_subnets", "vrf_id")

    def __init__(self, vpn_instance_id):
        self.vpn_instance_id = vpn_instance_id
        self.l3vni = None
        self.local_router_mac = None
        # {prefix_str: (remote_pe, remote_router_mac, ofport)}
        self.prefixes = {}
        # set of local OVS VLANs that belong to this L3VPN
        self.l2_vlans = set()
        # set of locally-attached subnet CIDRs (e.g. {"10.99.0.0/24"})
        self.local_subnets = set()
        # Locally-significant VRF ID (loaded into reg0 for table 50 isolation)
        self.vrf_id = None

    def __repr__(self):
        return ("IpvpnEviState(id=%s, l3vni=%s, vrf_id=%s, n_prefixes=%d, "
                "local_subnets=%s)" %
                (self.vpn_instance_id, self.l3vni, self.vrf_id,
                 len(self.prefixes), self.local_subnets))


class PerPeVxlanPortMgr:
    """Maintain at most one VXLAN port on br-tun per remote PE.

    Mirrors upstream ``TunnelManager`` from
    :mod:`networking_bagpipe.bagpipe_bgp.vpn.evpn.ovs` but uses the agent's
    working ``OVSTunnelBridge`` (passed in at construction).  Counts
    references so a port is only deleted when the last EVI that needed it
    drops its reference.

    Port name follows upstream:
    ``OVSNeutronAgent.get_tunnel_name(VXLAN, local_ip, remote_ip)``.
    The naming is irrelevant to forwarding; we keep the upstream form so
    an operator inspecting br-tun can correlate against tools that use the
    same convention.

    Each tunnel port is created with explicit ``local_ip`` set to the
    cross-cluster VTEP (CONF.BAGPIPE_XC.xc_local_ip).  This is critical:
    if we used the agent's intra-cluster ``local_ip``, OVS would source
    cross-cluster VXLAN packets from the wrong NIC.
    """

    def __init__(self, bridge, local_ip):
        self._bridge = bridge
        self._local_ip = local_ip
        self._refcount = collections.Counter()  # remote_ip -> count
        self._ofport = {}                       # remote_ip -> ofport
        self._lock = threading.Lock()

    def acquire(self, remote_ip):
        """Return the OF port number for ``remote_ip``, creating if needed."""
        with self._lock:
            if remote_ip in self._ofport:
                self._refcount[remote_ip] += 1
                return self._ofport[remote_ip]

            port_name = ovs_neutron_agent.OVSNeutronAgent.get_tunnel_name(
                n_consts.TYPE_VXLAN, self._local_ip, remote_ip)
            ofport = self._bridge.add_tunnel_port(port_name,
                                                  remote_ip,
                                                  self._local_ip,
                                                  n_consts.TYPE_VXLAN)
            # OVSTunnelBridge.add_tunnel_port returns int when successful;
            # negative or 0 means OVS refused to create the port.
            try:
                if int(ofport) <= 0:
                    LOG.error("xc: failed to add tunnel port for "
                              "remote_pe=%s (got ofport=%s)",
                              remote_ip, ofport)
                    return None
            except (TypeError, ValueError):
                LOG.error("xc: bridge.add_tunnel_port returned non-numeric "
                          "ofport for remote_pe=%s: %r", remote_ip, ofport)
                return None

            self._bridge.setup_tunnel_port(n_consts.TYPE_VXLAN, ofport)
            self._ofport[remote_ip] = ofport
            self._refcount[remote_ip] = 1
            LOG.info("xc: created tunnel port %s -> remote_pe=%s ofport=%s",
                     port_name, remote_ip, ofport)
            return ofport

    def release(self, remote_ip):
        """Drop a reference; delete the port when refcount reaches 0."""
        with self._lock:
            if remote_ip not in self._refcount:
                return
            self._refcount[remote_ip] -= 1
            if self._refcount[remote_ip] > 0:
                return

            ofport = self._ofport.pop(remote_ip, None)
            del self._refcount[remote_ip]
            if ofport is None:
                return
            try:
                # Reuse the same name we used at creation.
                port_name = ovs_neutron_agent.OVSNeutronAgent.get_tunnel_name(
                    n_consts.TYPE_VXLAN, self._local_ip, remote_ip)
                self._bridge.delete_port(port_name)
                LOG.info("xc: deleted tunnel port %s (remote_pe=%s)",
                         port_name, remote_ip)
            except Exception as exc:
                LOG.warning("xc: failed to delete tunnel port for "
                            "remote_pe=%s: %s", remote_ip, exc)


class _BagpipeLookingGlass:
    """Read-only client for bagpipe-bgp's looking-glass REST API.

    Wraps ``requests`` with sane timeouts and surfaces well-typed views.
    No state - every call hits bagpipe-bgp.  Errors are logged at WARNING
    and returned as empty data so the polling loop does not crash on
    transient failures.
    """

    def __init__(self, host, port, timeout):
        self._base = "http://%s:%d/looking-glass" % (host, port)
        self._timeout = timeout

    def _get(self, path):
        url = "%s/%s" % (self._base, path.lstrip("/"))
        try:
            resp = requests.get(url, timeout=self._timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            LOG.warning("xc: bagpipe-bgp REST GET %s failed: %s", url, exc)
            return None

    def list_evis(self):
        """Return a list of dicts with ``id`` and ``href`` for each EVI.

        Includes both ``evpn_`` (L2 EVI) and ``ipvpn_`` (L3 VPN) instances
        so Phase-2 can discover IPVPN instances for Type-5 route processing.
        """
        data = self._get("vpns/instances")
        if data is None:
            return []
        # Upstream emits a list of {id, name, description, href}.
        return [d for d in data
                if str(d.get("id", "")).startswith(("evpn_", "ipvpn_"))]

    def evi_routes(self, evi_id):
        """Return per-EVI routes (Type-2 unicast and Type-3 BUM).

        bagpipe-bgp 22.0.0 exposes routes under three sibling endpoints:

        * ``vpns/instances/<id>/best_routes`` - what this PE will act on.
          Object keyed by ``"('MAC', <mac>)"`` or ``"('Multicast', ...)"``;
          each value is a *list* of dicts whose single inner key is an
          NLRI string (parsed via :data:`_RE_T2` / :data:`_RE_T3`) and
          whose value is the route attributes (``next_hop``,
          ``route_targets``, ``attributes.extended-community``,
          ``attributes.pmsi-tunnel``).
        * ``received_routes`` - same shape as best_routes but includes
          duplicates / non-best-path entries.  We use ``best_routes`` for
          the dataplane install set.
        * ``adv_routes`` - what we are originating outward; not used for
          flow install.

        We yield a normalised iterable of dicts:

            {
                "type": 2|3,
                "mac": "fa:16:3e:..",   # only for type 2
                "ip":  "10.99.0.22",    # only for type 2 and only when present
                "vni": 9999,
                "remote_pe": "172.16.85.54",
            }

        Defensive about schema drift: any entry that fails to parse is
        logged at DEBUG and skipped.  The handler's reconcile cycle
        therefore degrades gracefully if bagpipe-bgp emits something we
        don't recognise.

        Phase-1 limitation: this parser is tuned for bagpipe-bgp 22.0.0
        (the 2024.2 / Dalmatian release line that ships in WRO 26.03).
        Other versions may drift; see the 'Schema reference' block in the
        module docstring.
        """
        data = self._get("vpns/instances/%s/best_routes" % evi_id)
        if data is None:
            return []
        out = []
        # ``data`` is a dict { "(<route-type>, <ident>)": [ {<inner_key>: route}, ... ] }
        for outer_key, route_list in (data.items() if isinstance(data, dict) else []):
            if not isinstance(route_list, list):
                continue
            for entry in route_list:
                if not isinstance(entry, dict) or not entry:
                    continue
                # Each entry is { <NLRI string>: { route attrs ... } }
                for inner_key, attrs in entry.items():
                    parsed = self._parse_route(inner_key, attrs)
                    if parsed:
                        out.append(parsed)
                    else:
                        LOG.debug("xc: unparseable route %r", inner_key)
        return out

    def evi_routes_raw(self, evi_id):
        """Return the raw JSON dict for an EVI's best_routes.

        Unlike :meth:`evi_routes` which parses into structured dicts, this
        returns a flat ``{inner_key: attrs}`` mapping suitable for
        inspecting route attributes (e.g. ``rmac:`` extended community)
        directly.  Used by Phase-2 to resolve local router MAC from
        looking-glass.
        """
        data = self._get("vpns/instances/%s/best_routes" % evi_id)
        if data is None:
            return {}
        flat = {}
        for outer_key, route_list in (data.items()
                                      if isinstance(data, dict) else []):
            if not isinstance(route_list, list):
                continue
            for entry in route_list:
                if not isinstance(entry, dict) or not entry:
                    continue
                for inner_key, attrs in entry.items():
                    flat[inner_key] = attrs
        return flat

    @staticmethod
    def _parse_route(inner_key, attrs):
        """Decode one inner-key NLRI string + its attribute dict."""
        if not isinstance(inner_key, str):
            return None
        next_hop = (attrs or {}).get("next_hop") if isinstance(attrs, dict) else None

        m = _RE_T2.match(inner_key)
        if m:
            return {
                "type": 2,
                "mac": m.group("mac").lower(),
                "ip": m.group("ip") if m.group("ip") else None,
                "vni": int(m.group("vni")),
                "remote_pe": next_hop or m.group("rd_pe"),
            }

        m = _RE_T3.match(inner_key)
        if m:
            # VNI is in attributes.pmsi-tunnel for Type-3.
            vni = None
            if isinstance(attrs, dict):
                pmsi = (attrs.get("attributes") or {}).get("pmsi-tunnel", "")
                pmsi_match = _RE_PMSI.search(pmsi)
                if pmsi_match:
                    vni = int(pmsi_match.group("vni"))
            return {
                "type": 3,
                "mac": None,
                "ip": None,
                "vni": vni,
                "remote_pe": next_hop or m.group("originator"),
            }

        # Phase-2: Type-5 IP Prefix route (inter-subnet routing)
        m = _RE_T5.match(inner_key)
        if m:
            rmac = None
            if isinstance(attrs, dict):
                ext_comm = (attrs.get("attributes") or {}).get(
                    "extended-community", "")
                rm = _RE_RMAC.search(ext_comm)
                if rm:
                    rmac = rm.group("mac").lower()
            return {
                "type": 5,
                "prefix": m.group("prefix"),
                "l3vni": int(m.group("l3vni")),
                "remote_pe": next_hop or m.group("rd_pe"),
                "remote_router_mac": rmac,
                "route_family": "evpn_type5",
                "mac": None,
                "ip": None,
                "vni": int(m.group("l3vni")),
            }


        return None


class EvpnXcHandler:
    """Owns all cross-cluster EVPN dataplane state for the local agent.

    Lifecycle:

    * Constructed by :class:`BagpipeBgpvpnAgentExtension` during
      ``initialize()``.  Receives the agent's ``tun_br`` (an
      ``OVSTunnelBridge`` with a working os-ken context) and its
      ``vlan_manager``.
    * Wraps ``tun_br`` in ``OVSBridgeWithGroups`` so we can use
      ``mod_group`` / ``delete_group`` for BUM head-end replication
      (matching upstream ``OVSEVIDataplane._update_flooding_buckets``).
    * Starts a :class:`FixedIntervalLoopingCall` that calls
      :meth:`reconcile_once` every ``xc_poll_interval`` seconds.
    * On agent shutdown, ``stop()`` cancels the loop.

    Concurrency:

    * Uses the same ``bagpipe-bgpvpn`` lockutils semaphore the agent
      extension uses for ``handle_port`` so reconciliation does not race
      with new port attachments.

    State:

    * ``self.evis`` maps ``vpn_instance_id -> EviState``.  Updated only
      under the lock.
    * ``self.tunnel_mgr`` is the per-PE OF port manager; refcounts let
      multiple EVIs share one tunnel to the same remote PE.
    """

    def __init__(self, tun_br, vlan_manager, networks_info_getter):
        if cfg.CONF.BAGPIPE_XC.xc_local_ip is None:
            raise ValueError(_(
                "BAGPIPE_XC.xc_local_ip is not configured.  Set this to "
                "the cross-cluster VTEP IP (matches "
                "[BGP] local_address in bgp.conf) before starting the "
                "OVS agent with the bagpipe_bgpvpn extension."))

        self._tun_br = tun_br
        self._bridge = dataplane_utils.OVSBridgeWithGroups(tun_br)
        self._vlan_manager = vlan_manager
        # Callable returning ``self.networks_info`` from the agent extension;
        # we use it to look up vni / network_id mappings on-demand.
        self._networks_info = networks_info_getter

        self._local_ip = cfg.CONF.BAGPIPE_XC.xc_local_ip
        self._lg = _BagpipeLookingGlass(
            host=cfg.CONF.BAGPIPE_XC.xc_bagpipe_api_host,
            port=cfg.CONF.BAGPIPE_XC.xc_bagpipe_api_port,
            timeout=cfg.CONF.BAGPIPE_XC.xc_request_timeout,
        )
        self.tunnel_mgr = PerPeVxlanPortMgr(self._bridge, self._local_ip)
        self.evis = {}  # vpn_instance_id -> EviState

        # Phase-2: Type-5 IPVPN state
        self.ipvpn_evis = {}   # vpn_instance_id -> IpvpnEviState
        self._next_vrf_id = 1
        self._vrf_id_map = {}  # vpn_instance_id -> locally-significant vrf_id

        self._loop = None
        LOG.info("xc: EvpnXcHandler initialized "
                 "(local_pe=%s, lg=%s:%d, poll=%ds, cookie=0x%x/0x%x)",
                 self._local_ip,
                 cfg.CONF.BAGPIPE_XC.xc_bagpipe_api_host,
                 cfg.CONF.BAGPIPE_XC.xc_bagpipe_api_port,
                 cfg.CONF.BAGPIPE_XC.xc_poll_interval, COOKIE, COOKIE_T5)

    @log_helpers.log_method_call
    def start(self):
        """Begin the periodic reconcile loop.  Idempotent."""
        if self._loop is not None:
            return
        self._loop = loopingcall.FixedIntervalLoopingCall(self._safe_reconcile)
        self._loop.start(interval=cfg.CONF.BAGPIPE_XC.xc_poll_interval,
                         initial_delay=1.0,
                         stop_on_exception=False)

    @log_helpers.log_method_call
    def stop(self):
        """Stop the loop and wait for the in-flight cycle to finish."""
        if self._loop is not None:
            self._loop.stop()
            self._loop = None

    def _safe_reconcile(self):
        """Wrap :meth:`reconcile_once` so a bad poll never kills the loop."""
        try:
            self.reconcile_once()
        except Exception:
            LOG.exception("xc: reconcile cycle failed (poll loop continues)")

    @lockutils.synchronized('bagpipe-bgpvpn')
    def reconcile_once(self):
        """Single poll cycle: read RIB, diff state, install/remove flows.

        Called every ``xc_poll_interval`` seconds and on demand from
        :meth:`ovs_restarted`.  Holds the same lockutils semaphore as the
        agent extension's port handlers so flow-install does not race
        with new attachments.
        """
        LOG.debug("xc: reconcile cycle starting")
        wanted = self._build_wanted_from_rib()

        # Reconcile per-EVI: ensure VLAN known, then diff entries.
        for evi_id, want in wanted.items():
            evi = self.evis.get(evi_id)
            if evi is None:
                evi = EviState(evi_id)
                self.evis[evi_id] = evi
            self._reconcile_evi(evi, want)

        # EVIs that disappeared from the RIB get torn down.
        gone = set(self.evis) - set(wanted)
        for evi_id in gone:
            evi = self.evis.pop(evi_id)
            self._tear_down_evi(evi)

        # --- Phase-2: Type-5 IPVPN reconcile ---
        wanted_ipvpn = self._build_wanted_ipvpn_from_rib()
        for evi_id, want in wanted_ipvpn.items():
            state = self.ipvpn_evis.get(evi_id)
            if state is None:
                state = IpvpnEviState(evi_id)
                self.ipvpn_evis[evi_id] = state
            self._reconcile_ipvpn_evi(state, want)

        gone_ipvpn = set(self.ipvpn_evis) - set(wanted_ipvpn)
        for evi_id in gone_ipvpn:
            state = self.ipvpn_evis.pop(evi_id)
            self._tear_down_ipvpn_evi(state)

        LOG.debug("xc: reconcile cycle done "
                  "(active_evis=%d, gone=%d, "
                  "active_ipvpn=%d, gone_ipvpn=%d)",
                  len(self.evis), len(gone),
                  len(self.ipvpn_evis), len(gone_ipvpn))

    # --- RIB ingestion ----------------------------------------------------

    def _build_wanted_from_rib(self):
        """Read bagpipe-bgp's looking-glass and return desired-state dict.

        Output:

        ```
        {
            "evpn_<net-uuid>": {
                "vni": 9999,
                "unicast": {mac: (ip, remote_pe)},
                "flooding": {remote_pe},
            },
            ...
        }
        ```

        This is the input to :meth:`_reconcile_evi`.  Locally-originated
        routes (``remote_pe == self._local_ip``) are filtered out for
        flooding (we don't head-end-replicate to ourselves), but kept for
        unicast so we know which MACs are local (used to skip Type-2 flow
        install since the OVS agent + l2pop already handles those).
        """
        wanted = {}
        for evi_meta in self._lg.list_evis():
            evi_id = evi_meta.get("id")
            if not evi_id:
                continue
            entry = {"vni": None, "unicast": {}, "flooding": set()}
            for r in self._lg.evi_routes(evi_id):
                # _parse_route already gave us {type, mac, ip, vni, remote_pe}
                rtype = r.get("type")
                remote_pe = r.get("remote_pe")
                vni = r.get("vni")
                if vni is not None:
                    # Last writer wins; all routes for one EVI share VNI.
                    entry["vni"] = int(vni)
                if rtype == 2:
                    mac = r.get("mac")
                    ip = r.get("ip")
                    if not mac or not remote_pe:
                        continue
                    if remote_pe == self._local_ip:
                        # Skip self-MACs - the OVS agent has them locally.
                        continue
                    entry["unicast"][mac] = (ip, remote_pe)
                elif rtype == 3:
                    if not remote_pe or remote_pe == self._local_ip:
                        continue
                    entry["flooding"].add(remote_pe)
            wanted[evi_id] = entry
        return wanted

    # --- Per-EVI reconciliation -------------------------------------------

    def _resolve_local_vlan(self, evi):
        """Find the OVS-agent-provisioned local VLAN for this EVI's network.

        The EVI ID encodes the Neutron network UUID
        (``evpn_<network-uuid>``).  The OVS agent's ``vlan_manager`` keys
        on (network_id, segment_id), so we need both.

        For VXLAN tenant networks the Neutron network's segmentation_id is
        the VNI; we use it directly.  For non-VXLAN networks, the BGPVPN
        association can supply a ``vni`` independently - in that case the
        Neutron segment_id may differ from the wire VNI.  Phase 1 supports
        only the VXLAN tenant network case (matches the cluster53/54
        deployment); non-VXLAN cases log a warning and skip.
        """
        # vpn_instance_id is "evpn_<net-uuid>"
        if not evi.vpn_instance_id.startswith("evpn_"):
            return None
        network_id = evi.vpn_instance_id[len("evpn_"):]
        if evi.vni is None:
            LOG.debug("xc: evi %s has no vni yet, skipping",
                      evi.vpn_instance_id)
            return None
        try:
            mapping = self._vlan_manager.get(network_id, evi.vni)
        except Exception:
            LOG.debug("xc: no vlan mapping for net=%s vni=%s",
                      network_id, evi.vni)
            return None
        return mapping.vlan

    def _reconcile_evi(self, evi, want):
        """Install/remove flows for one EVI to match ``want``."""
        evi.vni = want.get("vni") or evi.vni
        # Lazy-resolve the local VLAN; if no port has come up locally yet
        # we have nothing to forward to.  Skip the cycle for this EVI.
        local_vlan = self._resolve_local_vlan(evi)
        if local_vlan is None:
            return
        evi.vlan = local_vlan
        evi.local_pe = self._local_ip

        # ---- Type-2 unicast diff ----
        new_unicast = want["unicast"]
        for mac in set(new_unicast) - set(evi.unicast):
            ip, remote_pe = new_unicast[mac]
            ofport = self.tunnel_mgr.acquire(remote_pe)
            if ofport is None:
                continue
            self._install_unicast(evi, mac, ip, remote_pe, ofport)
            evi.unicast[mac] = (ip, remote_pe, ofport)
        for mac in set(evi.unicast) - set(new_unicast):
            ip, remote_pe, _ofport = evi.unicast.pop(mac)
            self._remove_unicast(evi, mac, ip)
            self.tunnel_mgr.release(remote_pe)

        # ---- Type-3 BUM diff ----
        new_flooding = want["flooding"]
        # Snapshot the installed set BEFORE mutating evi.flooding.  The
        # render decision below must compare against this pre-mutation
        # snapshot, not against new_flooding: after the add/remove loops
        # run, evi.flooding always equals new_flooding, so comparing the
        # two would never detect the initial empty -> non-empty transition
        # and the BUM flooding group/flow would never be built.
        old_flooding = set(evi.flooding)
        for remote_pe in new_flooding - old_flooding:
            ofport = self.tunnel_mgr.acquire(remote_pe)
            if ofport is None:
                continue
            evi.flooding[remote_pe] = ofport
        for remote_pe in old_flooding - new_flooding:
            evi.flooding.pop(remote_pe, None)
            self.tunnel_mgr.release(remote_pe)
        # Re-render whenever the installed set of remote PEs changed
        # (covers empty -> non-empty, additions, and removals/tear-down).
        if set(evi.flooding) != old_flooding:
            self._render_flooding(evi)

    # --- OpenFlow primitives ----------------------------------------------

    def _install_unicast(self, evi, mac, ip, remote_pe, ofport):
        """Install a UCAST_TO_TUN flow + ARP responder for one remote MAC.

        Mirrors ``OVSEVIDataplane.setup_dataplane_for_remote_endpoint``
        with two differences:

        * Adds a ``cookie`` so we can identify and delete fork flows.
        * Always uses the per-PE tunnel port (the local-PE shortcut in
          upstream is irrelevant here because we filter local routes
          before this point).
        """
        actions = "strip_vlan,set_tunnel:%d,output:%d" % (evi.vni, ofport)
        self._bridge.add_flow(
            table=ovs_const.UCAST_TO_TUN,
            priority=FLOW_PRIORITY,
            cookie=COOKIE,
            dl_vlan=evi.vlan,
            dl_dst=mac,
            actions=actions,
        )
        if ip:
            self._bridge.install_arp_responder(evi.vlan, str(ip), str(mac))
        LOG.debug("xc: installed unicast %s/%s -> remote_pe=%s vni=%d "
                  "ofport=%d (vlan=%d)",
                  mac, ip, remote_pe, evi.vni, ofport, evi.vlan)

    def _remove_unicast(self, evi, mac, ip):
        """Remove the UCAST_TO_TUN entry and ARP responder for one MAC."""
        self._bridge.delete_unicast_to_tun(evi.vlan, mac)
        if ip:
            self._bridge.delete_arp_responder(evi.vlan, str(ip))
        LOG.debug("xc: removed unicast %s/%s (vlan=%d)", mac, ip, evi.vlan)

    def _render_flooding(self, evi):
        """Rewrite the BUM head-end-replication group for this EVI.

        Identical to ``OVSEVIDataplane._update_flooding_buckets`` minus the
        local-port bucket: cross-cluster flooding never targets the local
        VTEP because the OVS agent's intra-cluster flooding already covers
        local delivery.

        ``mod_group`` replaces (or creates) group_id=evi.vlan with one
        bucket per remote PE.  The single FLOOD_TO_TUN flow then matches
        on (dl_vlan=evi.vlan) and dispatches via the group.
        """
        if not evi.flooding:
            # No remote PEs - tear down the flow + group entirely.
            try:
                self._bridge.delete_flows(
                    strict=True,
                    table=ovs_const.FLOOD_TO_TUN,
                    priority=FLOW_PRIORITY,
                    cookie=COOKIE,
                    dl_vlan=evi.vlan,
                )
            except Exception:
                pass
            try:
                self._bridge.delete_group(group_id=evi.vlan)
            except Exception:
                pass
            return

        buckets = []
        for remote_pe, ofport in evi.flooding.items():
            buckets.append("bucket=strip_vlan,set_tunnel:%d,output:%d" %
                           (evi.vni, ofport))
        self._bridge.mod_group(group_id=evi.vlan,
                               type='all',
                               buckets=','.join(buckets))
        self._bridge.add_flow(
            table=ovs_const.FLOOD_TO_TUN,
            priority=FLOW_PRIORITY,
            cookie=COOKIE,
            dl_vlan=evi.vlan,
            actions="group:%d" % evi.vlan,
        )
        LOG.debug("xc: rendered flooding for evi=%s vlan=%d "
                  "(%d remote PEs)",
                  evi.vpn_instance_id, evi.vlan, len(evi.flooding))

    def _tear_down_evi(self, evi):
        """Remove all fork-installed flows and groups for an evicted EVI."""
        for mac in list(evi.unicast):
            ip, remote_pe, _ofport = evi.unicast.pop(mac)
            try:
                self._remove_unicast(evi, mac, ip)
            except Exception:
                LOG.exception("xc: tear-down: failed to remove unicast %s",
                              mac)
            try:
                self.tunnel_mgr.release(remote_pe)
            except Exception:
                pass
        for remote_pe in list(evi.flooding):
            evi.flooding.pop(remote_pe, None)
            try:
                self.tunnel_mgr.release(remote_pe)
            except Exception:
                pass
        try:
            if evi.vlan is not None:
                self._render_flooding(evi)
        except Exception:
            LOG.exception("xc: tear-down: failed to clear flooding for %s",
                          evi.vpn_instance_id)
        LOG.info("xc: torn down evi=%s", evi.vpn_instance_id)

    # --- OVS restart hook --------------------------------------------------

    @lockutils.synchronized('bagpipe-bgpvpn')
    def ovs_restarted(self):
        """Called by the agent extension on OVS_RESTARTED.

        Because OVS lost all our flows and groups, we drop our cached
        state and let the next reconcile cycle reinstall everything.
        ``PerPeVxlanPortMgr`` also needs reset because OVS may have
        renumbered ofports.
        """
        LOG.warning("xc: OVS restart detected; clearing state and "
                    "letting next reconcile cycle reinstall flows")
        self.evis.clear()
        # Phase-2: clear IPVPN state and VRF allocator
        self.ipvpn_evis.clear()
        self._vrf_id_map.clear()
        self._next_vrf_id = 1
        # Replace the tunnel_mgr to reset its internal refcounts/ofports.
        self.tunnel_mgr = PerPeVxlanPortMgr(self._bridge, self._local_ip)

    # ======================================================================
    # Phase-2: Type-5 inter-subnet routing (Symmetric IRB in OVS)
    # ======================================================================

    def _get_vrf_id(self, vpn_instance_id):
        """Allocate a locally-significant VRF ID for table 50 reg0 isolation.

        IDs are monotonically increasing per agent lifetime (reset on OVS
        restart).  Supports up to 65535 VRFs (reg0[0..15]).
        """
        if vpn_instance_id not in self._vrf_id_map:
            self._vrf_id_map[vpn_instance_id] = self._next_vrf_id
            self._next_vrf_id += 1
        return self._vrf_id_map[vpn_instance_id]

    # --- Phase-2 OpenFlow primitives --------------------------------------

    def _install_prefix_route(self, state, prefix, remote_pe,
                              remote_router_mac, ofport):
        """Egress: routed IP prefix -> dec_ttl + MAC swap + L3VNI encap.

        Match includes dl_dst=<local_router_mac> to ensure only packets
        explicitly addressed to the local router (routed traffic) enter the
        L3 path.  Intra-subnet L2 traffic (dst_mac = remote VM MAC) will
        never match this flow.

        Installs one flow per l2_vlan in the VRF so packets from any
        locally-attached subnet can be routed to the remote prefix.
        """
        if self._is_local_prefix(prefix, state):
            LOG.debug("xc-t5: skipping locally-attached prefix %s for evi=%s",
                      prefix, state.vpn_instance_id)
            return False

        actions = (
            "dec_ttl,"
            "set_field:{lrmac}->eth_src,"
            "set_field:{rrmac}->eth_dst,"
            "strip_vlan,"
            "set_tunnel:{l3vni},"
            "output:{ofport}"
        ).format(
            lrmac=state.local_router_mac,
            rrmac=remote_router_mac,
            l3vni=state.l3vni,
            ofport=ofport,
        )
        for l2_vlan in state.l2_vlans:
            self._bridge.add_flow(
                table=ovs_const.UCAST_TO_TUN,
                priority=FLOW_PRIORITY + 1,
                cookie=COOKIE_T5,
                dl_vlan=l2_vlan,
                dl_dst=state.local_router_mac,
                dl_type=0x0800,
                nw_dst=prefix,
                actions=actions,
            )
        LOG.debug("xc-t5: installed prefix route %s -> remote_pe=%s "
                  "rmac=%s l3vni=%d ofport=%d (vlans=%s)",
                  prefix, remote_pe, remote_router_mac,
                  state.l3vni, ofport, state.l2_vlans)
        return True

    def _is_local_prefix(self, prefix, state):
        """Return True if prefix overlaps any locally-attached subnet.

        Prevents installing Type-5 egress flows for locally attached
        prefixes that are already reachable via the L2 Type-2 path.
        """
        target = ipaddress.ip_network(prefix, strict=False)
        for local_cidr in state.local_subnets:
            local_net = ipaddress.ip_network(local_cidr, strict=False)
            if target.overlaps(local_net):
                return True
        return False

    def _remove_prefix_route(self, state, prefix):
        """Remove egress prefix route flows for all local L2 VLANs."""
        for l2_vlan in state.l2_vlans:
            self._bridge.delete_flows(
                strict=True,
                table=ovs_const.UCAST_TO_TUN,
                priority=FLOW_PRIORITY + 1,
                cookie=COOKIE_T5,
                dl_vlan=l2_vlan,
                dl_dst=state.local_router_mac,
                dl_type=0x0800,
                nw_dst=prefix,
            )

    def _install_l3vni_ingress(self, state, ofport):
        """Ingress: L3VNI-tagged VXLAN -> load VRF ID into reg0, resubmit 50.

        Priority 7 (above standard l2pop TUN_TO_LV entries at priority 1)
        ensures L3VNI traffic is intercepted before the standard L2 decap
        path.
        """
        vrf_id = self._get_vrf_id(state.vpn_instance_id)
        self._bridge.add_flow(
            table=ovs_const.TUN_TO_LV,
            priority=FLOW_PRIORITY + 2,
            cookie=COOKIE_T5,
            in_port=ofport,
            tun_id=state.l3vni,
            actions="load:%d->NXM_NX_REG0[0..15],resubmit(,%d)" % (
                vrf_id, XC_L3_ROUTE_TABLE),
        )

    def _install_local_subnet_route(self, state, local_prefix, local_l2_vlan):
        """Re-bridge decapped L3VNI traffic into a local L2 subnet.

        Match on reg0=<vrf_id> ensures VRF isolation in table 50.
        After re-bridging, packet enters table 10 (LEARN) which delivers
        to patch-int and then to br-int for final-hop delivery via the
        neutron router's qr-xxx port.
        """
        vrf_id = self._get_vrf_id(state.vpn_instance_id)
        self._bridge.add_flow(
            table=XC_L3_ROUTE_TABLE,
            priority=FLOW_PRIORITY,
            cookie=COOKIE_T5,
            reg0=vrf_id,
            dl_type=0x0800,
            nw_dst=local_prefix,
            actions="mod_vlan_vid:%d,resubmit(,10)" % local_l2_vlan,
        )

    # --- Phase-2 reconcile helpers ----------------------------------------

    def _resolve_local_router_mac(self, vpn_instance_id):
        """Resolve local router MAC from bagpipe-bgp looking-glass.

        Strategy: find the local Type-5 route (next_hop == xc_local_ip) in
        this IPVPN instance and extract the rmac extended community.  This
        is authoritative - it's exactly what remote peers receive.

        Fallback: [BAGPIPE_XC] xc_local_router_mac config override.
        """
        try:
            routes = self._lg.evi_routes_raw(vpn_instance_id)
            for inner_key, attrs in routes.items():
                # Find local route (next_hop == our xc_local_ip)
                if not isinstance(attrs, dict):
                    continue
                next_hop = attrs.get("next_hop")
                if not next_hop:
                    next_hop = (attrs.get("attributes") or {}).get(
                        "next_hop")
                if next_hop != self._local_ip:
                    continue
                # Extract rmac from extended-community
                ext_comm = (attrs.get("attributes") or {}).get(
                    "extended-community", "")
                m = _RE_RMAC.search(ext_comm)
                if m:
                    return m.group("mac").lower()
        except Exception:
            LOG.debug("xc-t5: looking-glass query failed for %s",
                      vpn_instance_id, exc_info=True)

        # Fallback: config override
        configured = cfg.CONF.BAGPIPE_XC.xc_local_router_mac
        if configured:
            return configured.lower()

        return None

    def _resolve_local_subnets(self, vpn_instance_id):
        """Resolve locally-attached subnet CIDRs for this L3VPN instance.

        Queries looking-glass for local Type-5 routes (next_hop == self) -
        these are the prefixes this node owns.  Used by _is_local_prefix()
        guardrail.
        """
        local_subnets = set()
        try:
            routes = self._lg.evi_routes_raw(vpn_instance_id)
            for inner_key, attrs in routes.items():
                if not isinstance(attrs, dict):
                    continue
                next_hop = attrs.get("next_hop")
                if not next_hop:
                    next_hop = (attrs.get("attributes") or {}).get(
                        "next_hop")
                if next_hop != self._local_ip:
                    continue
                m = _RE_T5.match(inner_key)
                if m:
                    local_subnets.add(m.group("prefix"))
        except Exception:
            LOG.debug("xc-t5: failed resolving local subnets for %s",
                      vpn_instance_id, exc_info=True)
        return local_subnets

    def _local_vlans_for_l3vpn(self):
        """Resolve all local OVS VLANs from currently-tracked L2 EVIs.

        On AIO-SX (single host), all L2 EVIs are local so their VLANs are
        resolved.  On multi-compute, only locally-attached EVIs have a
        resolved VLAN.  We collect all resolved VLANs - the set represents
        all local subnets that can originate routed traffic.
        """
        vlans = set()
        for evi_state in self.evis.values():
            if evi_state.vlan is not None:
                vlans.add(evi_state.vlan)
        return vlans

    def _reconcile_ipvpn_evi(self, state, want):
        """Install/remove Type-5 flows for one IPVPN instance."""
        state.l3vni = want.get("l3vni") or state.l3vni
        state.local_router_mac = self._resolve_local_router_mac(
            state.vpn_instance_id)
        if not state.local_router_mac or not state.l3vni:
            LOG.debug("xc-t5: %s not ready (rmac=%s l3vni=%s)",
                      state.vpn_instance_id,
                      state.local_router_mac, state.l3vni)
            return

        state.l2_vlans = self._local_vlans_for_l3vpn()
        state.local_subnets = self._resolve_local_subnets(
            state.vpn_instance_id)
        state.vrf_id = self._get_vrf_id(state.vpn_instance_id)

        new_prefixes = want["prefixes"]

        # Install new prefix routes
        for prefix in set(new_prefixes) - set(state.prefixes):
            remote_pe, rmac = new_prefixes[prefix]
            if not rmac:
                LOG.warning("xc-t5: no rmac for prefix %s, skipping", prefix)
                continue
            ofport = self.tunnel_mgr.acquire(remote_pe)
            if ofport is None:
                continue
            installed = self._install_prefix_route(
                state, prefix, remote_pe, rmac, ofport)
            if installed:
                self._install_l3vni_ingress(state, ofport)
                state.prefixes[prefix] = (remote_pe, rmac, ofport)
            else:
                self.tunnel_mgr.release(remote_pe)

        # Install local subnet re-bridge rules in table 50
        for local_cidr in state.local_subnets:
            for l2_vlan in state.l2_vlans:
                self._install_local_subnet_route(state, local_cidr, l2_vlan)

        # Remove withdrawn prefix routes
        for prefix in set(state.prefixes) - set(new_prefixes):
            remote_pe, rmac, ofport = state.prefixes.pop(prefix)
            self._remove_prefix_route(state, prefix)
            self.tunnel_mgr.release(remote_pe)

    def _tear_down_ipvpn_evi(self, state):
        """Remove all Phase-2 flows for an evicted IPVPN instance."""
        for prefix in list(state.prefixes):
            remote_pe, rmac, ofport = state.prefixes.pop(prefix)
            try:
                self._remove_prefix_route(state, prefix)
            except Exception:
                LOG.exception("xc-t5: tear-down failed for prefix %s", prefix)
            try:
                self.tunnel_mgr.release(remote_pe)
            except Exception:
                pass
        # Clean up table 4 (L3VNI ingress) and table 50 flows for this VRF
        vrf_id = state.vrf_id
        if vrf_id is not None:
            self._bridge.delete_flows(
                table=XC_L3_ROUTE_TABLE,
                cookie=COOKIE_T5,
                reg0=vrf_id,
            )
        # Remove L3VNI ingress flows (table 4) matching this L3VNI
        if state.l3vni is not None:
            self._bridge.delete_flows(
                table=ovs_const.TUN_TO_LV,
                cookie=COOKIE_T5,
                tun_id=state.l3vni,
            )
        LOG.info("xc-t5: torn down ipvpn evi=%s (vrf_id=%s)",
                 state.vpn_instance_id, vrf_id)

    # --- Phase-2 RIB ingestion -------------------------------------------

    def _build_wanted_ipvpn_from_rib(self):
        """Read IPVPN instances from looking-glass and build wanted state.

        Output::

            {
                "ipvpn_<router-uuid>": {
                    "l3vni": 1000,
                    "prefixes": {
                        "10.98.0.0/24": ("172.16.85.54", "fa:16:3e:ab:cd:ef"),
                    },
                },
                ...
            }
        """
        wanted = {}
        for evi_meta in self._lg.list_evis():
            evi_id = evi_meta.get("id")
            if not evi_id or not evi_id.startswith("ipvpn_"):
                continue
            entry = {"l3vni": cfg.CONF.BAGPIPE_XC.xc_l3vni, "prefixes": {}}
            seen_type5 = 0
            skipped_missing_l3vni = 0
            skipped_missing_rmac = 0
            for r in self._lg.evi_routes(evi_id):
                if r.get("type") != 5:
                    continue
                if r.get("route_family") == "evpn_type5":
                    seen_type5 += 1
                remote_pe = r.get("remote_pe")
                if not remote_pe or remote_pe == self._local_ip:
                    continue
                prefix = r.get("prefix")
                l3vni = r.get("l3vni")
                rmac = r.get("remote_router_mac")
                if not prefix:
                    continue
                if not l3vni:
                    skipped_missing_l3vni += 1
                    continue
                if not rmac:
                    skipped_missing_rmac += 1
                    continue
                entry["l3vni"] = l3vni
                entry["prefixes"][prefix] = (remote_pe, rmac)

            if not seen_type5:
                LOG.debug(
                    "xc-t5: %s has no EVPN Type-5 routes yet "
                    "(prefixes=%d, missing_l3vni=%d, missing_rmac=%d)",
                    evi_id, len(entry["prefixes"]),
                    skipped_missing_l3vni, skipped_missing_rmac)
            if skipped_missing_l3vni or skipped_missing_rmac:
                LOG.debug(
                    "xc-t5: %s skipped prefixes (missing_l3vni=%d, "
                    "missing_rmac=%d)",
                    evi_id, skipped_missing_l3vni, skipped_missing_rmac)
            wanted[evi_id] = entry
        return wanted
