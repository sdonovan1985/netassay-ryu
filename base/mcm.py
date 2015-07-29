#########################
# NetAssay Project
#########################

# Copyright 2015 - Sean Donovan


import logging

from RegisteredMatchActions import *
from match-tracking import *
from Singleton import Singleton
from netaddr import EUI

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
        self.current_vmac = EUI("02:00:00:00:00:01") 

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
        if hashval is in self.vmac_table.keys():
            return self.vmac_table[hashval]
        self.current_vmac = EUI(int(self.current_vmac) + 1)
        self.vmac_table[hashval] = self.current_vmac

        return self.current_vmac

    def get_table(self):
        return self.table
        
    def register_NAMA(self, nama):
        self.match_actions.append(nama)






# Definition of the NetAssayMatchAction (NAMA).
# This is used by users of NetAssay. Based on 
# https://github.com/sdonovan1985/netassay/blob/master/pyretic/modules/netassay/netassaymatch.py
class NetAssayMatchAction(Object):
    
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
    def __init__(self, datapah, match, action, priority=1, postmatch=None):
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
        self.table = self.mcm.get_table()
        self.datapath = datapath

#TODO: Single ME now. Need changes to handle multiple MEs for a single NAMA
        # Create the new rule with the ME.
#        self.MEs = self._get_MEs()
#        self.MErules = self._create_ME_rules()
#        self._register_with_MEs()
        # FOR A SINGLE RULE ONLY
        rma = RegisteredMatchActions()
        self.ME = rma.lookup(self.match.keys()[1])
        self.MErule = self.ME.new_rule(self.match[self.match.keys()[1]])
        self.MErule.register_callbacks(self.add_rule, self.remove_rule)

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

    def add_rule(self, matchval):
        # If it already exists, just increment count. No need to install
        # a new OF rule.
        if matchval in self.trackers.keys:
            self.trackers[matchval].count += 1
        else:
            to_install = self.create_match_tracking(matchval)
            self.install_match(to_install)
            self.trackers[matchval] = to_install


    def remove_rule(self, matchval):
        # Make sure it exists
        if matchval in self.trackers.keys:
            # If there are multiple instances of the same rule, slightly
            # different behaviour. No need to remove the OF rule.
            if self.trackers[matchval].count > 1:
                self.trackers[matchval].count -= 1
            else:
                to_remove = self.trackers[matchval]
                del self.trackers[matchval]
                self.remove_match(to_remove)
        else:
            raise MainControlModuleException(
                "Trying to remove one that doesn't exists:\n    " +
                str(matchval))

    def create_match_tracking(self, match_string):
        cookie = self.mcm.get_cookie()
        #TODO: Create subaction (fwd to next table)
        subaction = 1 
        
        return match_tracking(match_string,
                              self.postmatch,
                              cookie,
                              subaction,
                              self,
                              self.vmac)
    
    def install_match(self, tracker):
        # This function handle installation of OF rules.
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        match = tracker.submatch
        actions = tracker.subactions
        cookie = tracker.cookie
        buffer_id = None

        #TODO: Should these be in the match_tracking class?
        priority = self.priority
        table = self.table
        

        # Push actions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        print "Adding flow : switch  " + str(datapath.id)
        print "            : match   " + str(match)
        print "            : actions " + str(actions)

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
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        match = tracker.submatch
        actions = tracker.subactions
        cookie = tracker.cookie
        buffer_id = None

        #TODO: Should this be in the match_tracking class?
        table = self.table

        print "Removing flow : switch  " + str(datapath.id)
        print "              : match   " + str(match)
        print "              : actions " + str(actions)

        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, 
                                table_id=table, command=ofproto_v1_3.OFPFC_DELETE,
                                out_group=ofproto_v1_3.OFPG_ANY, 
                                out_port=ofproto_v1_3.OFPP_ANY, 
                                match=match)
        datapath.send_msg(mod)
