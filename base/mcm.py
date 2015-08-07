#########################
# NetAssay Project
#########################

# Copyright 2015 - Sean Donovan


import logging

from RegisteredMatchActions import *
from match_tracking import *
from singleton import Singleton
from netaddr import EUI

from ryu.lib import mac as mac_lib
from ryu.ofproto import ofproto_v1_3

DEFAULT_TABLE = 2

# All MEs need to be called in here.
from me.dns.dnsme import *
METADATA_ENGINES = [DNSMetadataEngine()]




class MainControlModuleException(Exception):
    pass

# Defines the Main Control Module. Users of NetAssay have to initialize the MCM
# *before* trying to use any of the NetAssayMatchActions.
class NetAssayMCM(object):
    __metaclass__ = Singleton
        
    def __init__(self, table=DEFAULT_TABLE):

        self.setup_logger()
        self.logger.info("NetAssayMCM.__init__(): called")

        self.cookie = 1
        self.registrar = RegisteredMatchActions()
        self.match_actions = []
        self.vmac_table = {}
        self.current_vmac = 1 #EUI("02:00:00:00:00:01") 

        # Setup table
        self.table = table
        #TODO: anything else?
        
        # Get the MEs
        self.MEs = []
        for me in METADATA_ENGINES:
            self.MEs.append(me)

        # Finish
        self.logger.info("NetAssayMCM Initialized!")

    def setup_logger(self):
        formatter = logging.Formatter('%(asctime)s %(name)-12s: %(levelname)-8s %(message)s')
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
        console.setFormatter(formatter)
        logfile = logging.FileHandler('netassay.log')
        logfile.setLevel(logging.DEBUG)
        logfile.setFormatter(formatter)
        self.logger = logging.getLogger('netassay')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(console)
        self.logger.addHandler(logfile)        

    # The cookie is managed by the MCM so that unique cookies should be 
    # generated for each OF rule that is created.
    def get_cookie(self):
        retcookie = self.cookie
        self.cookie += 1
        self.logger.debug("NetAssayMCM.get_cookie(): %d" % retcookie)
        return retcookie

    # This allows for consisten VMACs based on the hashval passed in. The
    # hashval is the string that's being checked. For instance:
    #    "domain='example.com'" 
    # would be a hash value. This allows for the appropraite actions to be
    # taken in the 2nd level table.
    #TODO: should the hash be the match *and* the action? Maybe. If someone's
    #using a NAMA, they're probably also going to be ANDing it with something
    #else, such as 
    #    NAMA(domain='example.com') AND match(srcip=1.2.3.4) >> fwd(3)
    #I think just the match is fine as the hash because of this.
    def get_vmac(self, hashval):
        if hashval in self.vmac_table.keys():
            return self.vmac_table[hashval]
#SPD        self.current_vmac = EUI(int(self.current_vmac) + 1)
        self.current_vmac = self.current_vmac + 1
        self.vmac_table[hashval] = self.current_vmac

        return self.current_vmac

    def get_table(self):
        return self.table
        
    def register_NAMA(self, nama):
        self.match_actions.append(nama)






# Definition of the NetAssayMatchAction (NAMA).
# This is used by users of NetAssay. Based on 
# https://github.com/sdonovan1985/netassay/blob/master/pyretic/modules/netassay/netassaymatch.py
class NetAssayMatchAction(object):
    
    # match is a one entry dictionary - needs to be for now - may be fancier in
    #    the future
    # action are a list of actions that would typically be used in Ryu
    # priority is optional parameter, much like Ryu
    # postmatch is a secondary match action(s), also in a dictionary
    #    match is the NAMA match, postmatch is more traditional match variables 
    #    like in_port=1, or similar.
    #
    #TODO: Need to handle multiple match actions
    #    Could use multiple tables chained together for AND
    #    OR is simpler: same table, more entries.
    #TODO: Make match and postmatch easier to use
    def __init__(self, datapath, match, action, priority=1, table=0, postmatch=None):
        self.match = match
        self.action = action
        self.postmatch = postmatch
        self.priority = priority
        

        # Initialize tracking structures
        self.trackers = {}

        # Register with MCM
        self.mcm = NetAssayMCM()
        self.mcm.register_NAMA(self)
        self.vmac = self.mcm.get_vmac(str(self.match) + 
                                      str(self.postmatch))
        self.mcmtable = self.mcm.get_table()
        self.subtable = table
        self.datapath = datapath
        self.cookie = self.mcm.get_cookie()

        # Install rule in MCM's table for future action
        self.install_mcm_table_match()

#TODO: Single ME now. Need changes to handle multiple MEs for a single NAMA
        # Create the new rule with the ME.
#        self.MEs = self._get_MEs()
#        self.MErules = self._create_ME_rules()
#        self._register_with_MEs()
        # FOR A SINGLE RULE ONLY
        rma = RegisteredMatchActions()
        self.ME = rma.lookup(self.match.keys()[0])
        self.MErule = self.ME.new_rule(self.match[self.match.keys()[0]],
                                       self.add_rule, self.remove_rule)
#        self.MErule.register_callbacks(self.add_rule, self.remove_rule)

    def __del__(self):
        #TODO - This should clean up all the rules associated. 
        pass

    def _get_MEs(self):
        me_list = []
        rma = RegisteredMatchActions()
        for key in self.match.keys():
            me_list.append(rma.lookup(self.match.keys()[1]))
        
        return me_list

    def _create_ME_rules(self):
        #TODO: For each ME, create rule that they're responsible for.
        pass
    
    def _register_with_MEs(self):
        #TODO: for multiple MEs in a single NAMA. Not used right now.
        for me in self.MEs:
            me.register_update_callback(self.update_callback)

    def add_rule(self, **kwargs):
        # If it already exists, just increment count. No need to install
        # a new OF rule.
        matchval = kwargs
#        print "add_rule: " + str(matchval)
        strval = str(matchval)
        if strval in self.trackers.keys():
            self.trackers[strval].count += 1
        else:
            to_install = self.create_match_tracking(matchval)
            self.install_match(to_install)
            self.trackers[strval] = to_install


    def remove_rule(self, **kwargs):
        # Make sure it exists
        matchval = kwargs
#        print "remove_rule: " + str(matchval)
        strval = str(matchval)
        if strval in self.trackers.keys():
            # If there are multiple instances of the same rule, slightly
            # different behaviour. No need to remove the OF rule.
            if self.trackers[strval].count > 1:
                self.trackers[strval].count -= 1
            else:
                to_remove = self.trackers[strval]
                del self.trackers[strval]
                self.remove_match(to_remove)
        else:
            print "We have the following valid rules:"
            for key in self.trackers.keys():
                print "    " + str(key)
            raise MainControlModuleException(
                "Trying to remove one that doesn't exists:\n    " +
                str(matchval))

    def create_match_tracking(self, match_kwargs):
        cookie = self.mcm.get_cookie()

        parser = self.datapath.ofproto_parser
#SPD        subaction = [parser.OFPActionOutput(2)]
        subaction = [parser.OFPInstructionWriteMetadata(self.vmac, 4095)]
        
        return match_tracking(match_kwargs,
                              self.postmatch,
                              cookie,
                              subaction,
                              self,
                              self.vmac)
    
    def install_match(self, tracker):
        # This function handle installation of OF rules.
        datapath = self.datapath
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        match = parser.OFPMatch(**tracker.submatch)
#        print "**** INSTALL_MATCH ****: " + str(match)
        actions = tracker.subactions

#        match = parser.OFPMatch(eth_type=2048, ipv4_src='54.201.8.79', in_port=3)
#        actions = [parser.OFPActionOutput(2)]

        cookie = tracker.cookie
        buffer_id = None

        #TODO: Should these be in the match_tracking class?
        priority = self.priority
        table = self.subtable

        tracker.ofpmatch = match
        

        # Push actions
#        for a in actions:
#            print str(a) + " " + str(type(a))
        
        inst = actions
#        [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
#                                             actions),
#                parser.OFPInstructionGotoTable(self.subtable)]
        inst.append(parser.OFPInstructionGotoTable(self.mcm.get_table()))


        print "    NETASSAY"
        print "Adding flow : switch   " + str(datapath.id)
        print "            : priority " + str(priority)
        print "            : match    " + str(match)
        print "            : actions  " + str(actions)
        

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, 
                                    table_id=table)

        datapath.send_msg(mod)
        

    def remove_match(self, tracker):
        # This function removes OF rules.
        datapath = self.datapath
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        match = tracker.ofpmatch
        actions = tracker.subactions
        cookie = tracker.cookie
        buffer_id = None

        #TODO: Should this be in the match_tracking class?
        table = self.subtable

#        print "Removing flow : switch  " + str(datapath.id)
#        print "              : match   " + str(match)
#        print "              : actions " + str(actions)

        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, 
                                table_id=table, command=ofproto_v1_3.OFPFC_DELETE,
                                out_group=ofproto_v1_3.OFPG_ANY, 
                                out_port=ofproto_v1_3.OFPP_ANY, 
                                match=match)
        datapath.send_msg(mod)


    def install_mcm_table_match(self):
        # This function handle installation of OF rules.
        datapath = self.datapath
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        match = parser.OFPMatch(metadata=self.vmac)
        actions = self.action
        cookie = self.cookie
        buffer_id = None

        #TODO: Should these be in the match_tracking class?
        priority = self.priority
        table = self.mcmtable
        

        # Push actions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

#        print "Adding flow : switch  " + str(datapath.id)
#        print "            : match   " + str(match)
#        print "            : actions " + str(actions)

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, 
                                    table_id=table)

        datapath.send_msg(mod)
        

    def remove_mcm_table_match(self):
        # This function removes OF rules.
        datapath = self.datapath
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        match = self.match
        actions = self.actions
        cookie = self.cookie
        buffer_id = None

        #TODO: Should this be in the match_tracking class?
        table = self.mcmtable

#        print "Removing flow : switch  " + str(datapath.id)
#        print "              : match   " + str(match)
#        print "              : actions " + str(actions)

        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, 
                                table_id=table, command=ofproto_v1_3.OFPFC_DELETE,
                                out_group=ofproto_v1_3.OFPG_ANY, 
                                out_port=ofproto_v1_3.OFPP_ANY, 
                                match=match)
        datapath.send_msg(mod)
