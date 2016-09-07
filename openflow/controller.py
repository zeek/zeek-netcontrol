#!/usr/bin/env python

# Ryu OpenFlow controller that connects to the Bro OpenFlow
# framework using Broker.
#
# Start with ./ryu/bin/ryu-manager controller.py

import logging
import time
import re
import ryu.app.ofctl.api
from netaddr import IPNetwork

from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import controller
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib import hub

from pybroker import *
from select import select

supported_ofctl = {
    ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
    ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
}

queuename = "bro/event/openflow"

# for monkey-patching.
# Barf.
def bro_send_msg(self, msg):
    assert isinstance(msg, self.ofproto_parser.MsgBase)

    if not hasattr(self, 'brosend'):
        self.brosend = 0
        self.bromessage = None

    # if we set before that we just want the message returned
    # without sending it on - return it to us so we can use
    # it further...
    if ( self.brosend == 1 ):
        self.brosend = 0
        self.bromessage = msg
        return msg

    self.send_msg_orig(msg)

# sorry about all that. This is just to get the API somewhere where we actually can work
# with it.
# :/
ryu.controller.controller.Datapath.send_msg_orig = ryu.controller.controller.Datapath.send_msg
ryu.controller.controller.Datapath.send_msg = bro_send_msg

class BroController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(BroController, self).__init__(*args, **kwargs);

        self.dpset = kwargs['dpset']
        self.data = {}
        self.data['dpset'] = self.dpset
        # store DPID->name mapping. We create the mapping implicitely
        # for all flow_clear and flow_mod events that we get and use
        # it for the returning flow_removed events
        self.dpids = {}

        self.epl = endpoint("listener")

    def start(self):
        self.epl.listen(9999, "127.0.0.1")
        self.icsq = self.epl.incoming_connection_status()
        self.mql = message_queue(queuename, self.epl)
        self.threads.append(hub.spawn(self._broker_loop))
        self.logger.info("Started broker communication...")
        self.threads.append(hub.spawn(self._event_loop))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp = ev.msg.datapath
        # here we could alarm that we have seen a new switch

    def _broker_loop(self):
        self.logger.info("Broker loop...")

        while 1==1:
            self.logger.info("Waiting for broker message")
            readable, writable, exceptional = select([self.icsq.fd(), self.mql.fd()],[],[])
            msgs = None
            if ( self.icsq.fd() in readable ):
                msgs = self.icsq.want_pop()
            elif ( self.mql.fd() in readable ):
                msgs = self.mql.want_pop()

            for m in msgs:
                self.logger.info("Got broker message")
                self.handle_broker_message(m)

    def handle_broker_message(self, m):
        if ( type(m).__name__ == "incoming_connection_status" ):
            self.logger.info("Incoming connection established")
            return

        if ( type(m).__name__ != "tuple" ):
            self.logger.error("Unexpected type %s, expected tuple", type(m).__name__)
            return

        if ( len(m) < 1 ):
            self.logger.error("Tuple without content?")
            return

        event_name = str(m[0])

        if ( event_name == "OpenFlow::broker_flow_clear" ):
            self.event_flow_clear(m)
        elif ( event_name == "OpenFlow::broker_flow_mod" ):
            self.event_flow_mod(m)
        elif event_name == "OpenFlow::flow_mod_success":
            pass
        elif event_name == "OpenFlow::flow_mod_failure":
            pass
        elif event_name == "OpenFlow::flow_removed":
            pass
        else:
            self.logger.error("Unknown event %s", event_name)
            return

    def event_flow_clear(self, m):
        if ( len(m) != 3 ) or ( m[1].which() != data.tag_string ) or ( m[2].which() != data.tag_count ):
            self.logger.error("wrong number of elements or type in tuple for event_flow_clear")
            return

        # since this is really only a  convenience function we should return it and just do the
        # flow-mod from bro ourselves
        name = m[1].as_string()

        dpid = m[2].as_count()
        self.logger.info("flow_clear for %s %d", name, dpid)

        dp = ryu.app.ofctl.api.get_datapath(self, int(dpid))

        if dp is None:
            self.logger.error("dpid %d not found for clear", dpid)
            return

        self.dpids[dp.id] = name

        flow = {'table_id': dp.ofproto.OFPTT_ALL}
        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is None:
            self.logger.error("unsupported openflow protocol")
            return

        dp.brosend = 1 # give it to us
        _ofctl.mod_flow_entry(dp, flow, dp.ofproto.OFPFC_DELETE)
        msg = dp.bromessage

        ryu.app.ofctl.api.send_msg(self, msg)

    def send_error(self, name, match, flow_mod, msg):
        m = message([data("OpenFlow::flow_mod_failure")])
        m.push_back(data(name))
        m.push_back(match)
        m.push_back(flow_mod)
        m.push_back(data(msg))
        self.epl.send(queuename, m)

    def send_success(self, name, match, flow_mod, msg):
        m = message([data("OpenFlow::flow_mod_success"), data(name), match, flow_mod, data(msg)])
        self.epl.send(queuename, m)

    def event_flow_mod(self, m):
        if ( len(m) != 5 ) or ( m[1].which() != data.tag_string ) or ( m[2].which() != data.tag_count ) or ( m[3].which() != data.tag_record ) or ( m[4].which() != data.tag_record ):
            self.logger.error("wrong number of elements or type in tuple for event_flow_mod")
            return

        name = m[1].as_string()

        dpid = m[2].as_count()
        match = self.parse_ofp_match(m[3])
        flow_mod = self.parse_ofp_flow_mod(m[4])

        dp = ryu.app.ofctl.api.get_datapath(self, int(dpid))

        if dp is None:
            self.logger.error("name %s dpid %d not found for flow_mod", name, dpid)
            self.send_error(m[3], m[4], "dpid not found")
            return

        self.dpids[dp.id] = name

        if dp.ofproto.OFP_VERSION != ofproto_v1_0.OFP_VERSION:
            if 'nw_dst' in match:
                if ":" in match['nw_dst']:
                    match['ipv6_dst'] = match['nw_dst']
                else:
                    match['ipv4_dst'] = match['nw_dst']
                del match['nw_dst']

            if 'nw_src' in match:
                if ":" in match['nw_src']:
                    match['ipv6_src'] = match['nw_src']
                else:
                    match['ipv4_src'] = match['nw_src']
                del match['nw_src']

            if 'tp_src' in match:
                proto = match.get('nw_proto', None);
                if proto == None:
                    self.logger.error("Cannot determine proto for flow mod")
                    return

                if proto == 0x06:
                    match['tcp_src'] = match['tp_src']
                    del match['tp_src']
                elif proto == 0x11:
                    match['udp_src'] = match['tp_src']
                    del match['tp_src']
                elif proto == 0x01:
                    match['icmpv4_type'] = match['tp_src']
                    del match['tp_src']


            if 'tp_dst' in match:
                proto = match.get('nw_proto', None);
                if proto == None:
                    self.logger.error("Cannot determine proto for flow mod")
                    return

                if proto == 0x06:
                    match['tcp_dst'] = match['tp_dst']
                    del match['tp_dst']
                elif proto == 0x11:
                    match['udp_dst'] = match['tp_dst']
                    del match['tp_dst']
                elif proto == 0x01:
                    match['icmpv4_code'] = match['tp_dst']
                    del match['tp_dst']

        self.logger.info("flow_mod for %d", dpid)
        #print match
        #print flow_mod


        cmdstr = flow_mod['command']
        cmd = self.string_to_command(dp, cmdstr)

        flow_mod['match'] = match
        #flow_mod['flags'] = 1 # remove, we actually want overlapping entries sometimes.
        actions = []

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            for k, v in flow_mod['actions'].iteritems():
                if k == 'vlan_vid':
                    actions.append(dp.ofproto_parser.OFPActionVlanVid(v))
                elif k == 'vlan_pcp':
                    actions.append(dp.ofproto_parser.OFPActionVlanPcp(k))
                elif k == 'vlan_strip' and v == True:
                    actions.append(dp.ofproto_parser.OFPActionStripVlan())
                elif k == 'dl_src':
                    dl_src = haddr_to_bin(v)
                    actions.append(dp.ofproto_parser.OFPActionSetDlSrc(dl_src))
                elif k == 'dl_dst':
                    dl_dst = haddr_to_bin(v)
                    actions.append(dp.ofproto_parser.OFPActionSetDlDst(dl_dst))
                elif k == 'nw_tos':
                    actions.append(dp.ofproto_parser.OFPActionSetNwTos(v))
                elif k == 'nw_src':
                    actions.append(dp.ofproto_parser.OFPActionSetNwSrc(ipv4_to_int(v)))
                elif k == 'nw_dst':
                    actions.append(dp.ofproto_parser.OFPActionSetNwDst(ipv4_to_int(v)))
                elif k == 'tp_src':
                    actions.append(dp.ofproto_parser.OFPActionSetTpSrc(v))
                elif k == 'tp_dst':
                    actions.append(dp.ofproto_parser.OFPActionSetTpDst(v))
        else:

            if 'nw_dst' in flow_mod['actions']:
                if ":" in flow_mod['actions']['nw_dst']:
                    flow_mod['actions']['ipv6_dst'] = flow_mod['actions']['nw_dst']
                else:
                    flow_mod['actions']['ipv4_dst'] = flow_mod['actions']['nw_dst']
                del flow_mod['actions']['nw_dst']

            if 'nw_src' in flow_mod['actions']:
                if ":" in flow_mod['actions']['nw_src']:
                    flow_mod['actions']['ipv6_src'] = flow_mod['actions']['nw_src']
                else:
                    flow_mod['actions']['ipv4_src'] = flow_mod['actions']['nw_src']
                del flow_mod['actions']['nw_src']

            if 'tp_src' in flow_mod['actions']:
                proto = match.get('nw_proto', None);
                if proto == None:
                    self.logger.error("Cannot determine proto for flow mod")
                    return

                if proto == 0x06:
                    flow_mod['actions']['tcp_src'] = flow_mod['actions']['tp_src']
                elif proto == 0x11:
                    flow_mod['actions']['udp_src'] = flow_mod['actions']['tp_src']
                elif proto == 0x01:
                    flow_mod['actions']['icmpv4_type'] = flow_mod['actions']['tp_src']

            if 'tp_dst' in flow_mod['actions']:
                proto = match.get('nw_proto', None);
                if proto == None:
                    self.logger.error("Cannot determine proto for flow mod")
                    return

                if proto == 0x06:
                    flow_mod['actions']['tcp_dst'] = flow_mod['actions']['tp_dst']
                elif proto == 0x11:
                    flow_mod['actions']['udp_dst'] = flow_mod['actions']['tp_dst']
                elif proto == 0x01:
                    flow_mod['actions']['icmpv4_code'] = flow_mod['actions']['tp_dst']

            for k, v in flow_mod['actions'].iteritems():
                if k == 'vlan_strip' and v == True:
                    actions.append(dp.ofproto_parser.OFPActionStripVlan())
                elif ( k == 'vlan_vid' ) or ( k == 'vlan_pcp' ) or ( k == 'nw_tos' ) or ( k == 'ipv4_src' ) or ( k == 'ipv4_dst' ) or ( k == 'tcp_src' ) or ( k == 'tcp_dst' ) or ( k == 'udp_src' ) or ( k == 'udp_dst' ) or ( k == 'icmpv4_code' ) or ( k == 'icmpv4_type' ) or ( k == 'ipv6_src' ) or ( k == 'ipv6_dst' ):
                    pass
                    actions.append(dp.ofproto_parser.OFPActionSetField(**{k: v}))
                elif ( k == 'dl_src' ) or ( k == 'dl_dst' ):
                    #dl = haddr_to_bin(v)
                    actions.append(dp.ofproto_parser.OFPActionSetField(**{k: v}))

        # do out-ports separately because it has to be last...
        if 'out_ports' in flow_mod['actions']:
            for i in flow_mod['actions']['out_ports']:
                max_len = 0xffe5
                if dp.ofproto.OFP_VERSION != ofproto_v1_0.OFP_VERSION:
                    max_len = dp.ofproto.OFPCML_MAX

                if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
                    if i == 0xfffffff8:
                        i = dp.ofproto.OFPP_IN_PORT
                    elif i == 0xfffffff9:
                        i = dp.ofproto.OFPP_TABLE
                    elif i == 0xfffffffa:
                        i = dp.ofproto.OFPP_NORMAL
                    elif i == 0xfffffffb:
                        i = dp.ofproto.OFPP_FLOOD
                    elif i == 0xfffffffc:
                        i = dp.ofproto.OFPP_ALL
                    elif i == 0xfffffffd:
                        i = dp.ofproto.OFPP_CONTROLLER
                    elif i == 0xfffffffe:
                        i = dp.ofproto.OFPP_LOCAL
                    elif i == 0xffffffff:
                        i = dp.ofproto.OFPP_ANY

                actions.append(dp.ofproto_parser.OFPActionOutput(i, max_len))

        del flow_mod['actions']

        if cmd is None:
            self.logger.error("command %s could not be parsed", cmdstr)
            self.send_error(m[3], m[4], "cmd not recognized")
            return

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is None:
            self.logger.error("unsupported openflow protocol")
            self.send_error(m[3], m[4], "unsupported openflow protocol")
            return

        dp.brosend = 1 # give it to us...
        _ofctl.mod_flow_entry(dp, flow_mod, cmd)
        msg = dp.bromessage

        # naming and calling changed in the api for of1.0 vs 1.3

        insts = []
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            msg.actions = actions
        else:
            insts.append(dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions))
            msg.instructions = insts

        #print "Sending to switch:"
        #print msg

        try:
            ryu.app.ofctl.api.send_msg(self, msg)
            self.send_success(name, m[3], m[4], "")
        except ryu.app.ofctl.exception.OFError as err:
            self.logger.error("flow_mod execution error %s", err)
            self.send_error(name, m[3], m[4], str(err))

    def parse_ofp_match(self, m):
        match = ['in_port', 'dl_src', 'dl_dst', 'dl_vlan', 'dl_vlan_pcp', 'dl_type', 'nw_tos', 'nw_proto', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst']
        return self.record_to_record(match, m)


    def parse_ofp_flow_mod(self, m):
        match = ['cookie', 'table_id', 'command', 'idle_timeout', 'hard_timeout', 'priority', 'out_port', 'out_group', 'flags']

        rec = self.record_to_record(match, m)

        # ok, now we have to get the actions, which are after flags. This is kind of cheating, but... whatever :)
        match_actions = ['out_ports', 'vlan_vid', 'vlan_pcp', 'vlan_strip', 'dl_src', 'dl_dst', 'nw_tos', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst']

        rm = m.as_record()
        rl = rm.fields()[9]
        recaction = self.record_to_record(match_actions, rl.get())
        rec['actions'] = recaction

        return rec

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        match = msg.match

        if dp.id not in self.dpids:
            self.logger.error("Flow remove for unknown DPID %d", dp.id)
            return

        #print "Flow removed"

        match_vec = vector_of_field([])
        match_vec = self.vec_add_field(match_vec, match, 'in_port');
        match_vec = self.vec_add_field(match_vec, match, 'eth_src');
        match_vec = self.vec_add_field(match_vec, match, 'eth_dst');
        match_vec = self.vec_add_field(match_vec, match, 'vlan_vid');
        match_vec = self.vec_add_field(match_vec, match, 'vlan_pcp');
        match_vec = self.vec_add_field(match_vec, match, 'eth_type');
        match_vec = self.vec_add_field(match_vec, match, 'ip_dscp');
        match_vec = self.vec_add_field(match_vec, match, 'ip_proto');

        src = match.get('ipv4_src', match.get('ipv6_src', match.get('nw_src', None)))
        dst = match.get('ipv4_dst', match.get('ipv6_dst', match.get('nw_dst', None)))

        if src != None:
            sn = None
            if ( not isinstance(src, tuple) ) and( ":" in src ):
                sn = subnet(address.from_string(src), 128)
            elif not isinstance(src, tuple):
                sn = subnet(address.from_string(src), 32)
            else:
                adr = address.from_string(src[0])
                ip = IPNetwork(src[0]+"/"+src[1])
                sn = subnet(adr, ip.prefixlen)
            match_vec.push_back(field(data(sn)))
        else:
            match_vec.push_back(field())

        if dst != None:
            sn = None
            if ( not isinstance(dst, tuple) ) and( ":" in dst ):
                sn = subnet(address.from_string(dst), 128)
            elif not isinstance(dst, tuple):
                sn = subnet(address.from_string(dst), 32)
            else:
                adr = address.from_string(dst[0])
                ip = IPNetwork(dst[0]+"/"+dst[1])
                sn = subnet(adr, ip.prefixlen)
            match_vec.push_back(field(data(sn)))
        else:
            match_vec.push_back(field())

        srcp = match.get('tcp_src', match.get('udp_src', match.get('icmpv4_type', match.get('tp_src', None))))
        dstp = match.get('tcp_dst', match.get('udp_dst', match.get('icmpv4_type', match.get('tp_dst', None))))

        if srcp != None:
            match_vec.push_back(field(data(srcp)))
        else:
            match_vec.push_back(field())

        if dstp != None:
            match_vec.push_back(field(data(dstp)))
        else:
            match_vec.push_back(field())

        m = message([data("OpenFlow::flow_removed"), data(self.dpids[dp.id]), data(record(match_vec)), data(msg.cookie), data(msg.priority), data(msg.reason), data(msg.duration_sec), data(msg.idle_timeout), data(msg.packet_count), data(msg.byte_count)])
        self.epl.send(queuename, m)


    def vec_add_field(self, match_vec, match , el):
        if el in match:
            match_vec.push_back(field(data(match[el])))
        else:
            match_vec.push_back(field())

        return match_vec

    def string_to_command(self, dp, cmdstr):
        if ( cmdstr == "OFPFC_ADD" ):
            return dp.ofproto.OFPFC_ADD
        elif ( cmdstr == "OFPFC_MODIFY" ):
            return dp.ofproto.OFPFC_MODIFY
        elif ( cmdstr == "OFPFC_MODIFY_STRICT" ):
            return dp.ofproto.OFPFC_MODIFY_STRICT
        elif ( cmdstr == "OFPFC_DELETE" ):
            return dp.ofproto.OFPFC_DELETE
        elif ( cmdstr == "OFPFC_DELETE_STRICT" ):
            return dp.ofproto.OFPFC_DELETE_STRICT
        else:
            return None

    def record_to_record(self, match, m):

        #if len(match) != len(m):
        #    self.logger.error("wrong number of elements in parse_ofp_match")
        #    return

        if m.which() != data.tag_record:
            self.logger.error("Got non record element")

        rec = m.as_record()

        dict = {}
        for i in range(0, len(match)):
            if rec.fields()[i].valid() == False:
                #dict[match[i]] = None # most of the functions expect this to be undefined, not none. We oblige.
                continue

            dict[match[i]] = self.convert_element(rec.fields()[i].get())

        return dict

    def convert_element(self, el):
        if ( el.which() == data.tag_boolean ):
            return el.as_bool()
        if ( el.which() == data.tag_count ):
            return el.as_count()
        elif ( el.which() == data.tag_integer ):
            return el.as_int()
        elif ( el.which() == data.tag_real ):
            return el.as_real()
        elif ( el.which() == data.tag_string ):
            return el.as_string()
        elif ( el.which() == data.tag_address ):
            return str(el.as_address())
        elif ( el.which() == data.tag_subnet ):
            return str(el.as_subnet())
        elif ( el.which() == data.tag_port ):
            return el.as_port().number()
        elif ( el.which() == data.tag_time ):
            return el.as_time()
        elif ( el.which() == data.tag_duration ):
            return el.as_duration().value
        elif ( el.which() == data.tag_enum_value ):
            tmp = el.as_enum().name
            return re.sub(r'.*::', r'', tmp)
        elif ( el.which() == data.tag_vector ):
            tmp = el.as_vector()
            elements = []
            for sel in tmp:
                elements.append(self.convert_element(sel))
            return elements

        else:
            self.logger.error("Unsupported type %d", el.which() )
            return None


