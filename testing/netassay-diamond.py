# Copyright 2015 - Sean Donovan
# Based on non-netassay-diamon.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from base.mcm import *

class Diamond(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Diamond, self).__init__(*args, **kwargs)
        self.mcm = NetAssayMCM()
        self.NAMAs = []
        print "__init__() complete."

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

#        match = parser.OFPMatch()
#        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
#                                          ofproto.OFPCML_NO_BUFFER)]
#        self.add_flow(datapath, 0, match, actions)

        print "Datapath ID: " + str(datapath.id)
        if(datapath.id == 3 or datapath.id == 4):
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.add_flow(datapath, 0, match, actions)
        elif(datapath.id == 2 or datapath.id == 1):
            match = parser.OFPMatch(in_port=1)
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 0, match, actions)

            match = parser.OFPMatch(in_port=2)
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 0, match, actions)

            match = {'domain':"google.com"}
            actions = [parser.OFPActionOutput(2)]
#            NetAssayMatchAction(datapath, match, action)
            self.NAMAs.append(NetAssayMatchAction(datapath, match, 
                                                  actions, priority=10))

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        print "Adding flow : switch   " + str(datapath.id)
        print "            : priority " + str(priority)
        print "            : match    " + str(match)
        print "            : actions  " + str(actions)

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
