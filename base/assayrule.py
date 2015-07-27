# Copyright 2014 - Sean Donovan
# This defines rules for NetAssay.

import logging
from ipaddr import IPv4Network, CollapseAddrList
from pyretic.core.language import Match, basic_headers, tagging_headers
from pyretic.modules.netassay.rulelimiter import RuleLimiter
from pyretic.modules.netassay.lib.py_timer import py_timer as Timer

from pyretic.modules.netassay.eval.serial_logging import serial_logging


TIMEOUT = 0.1

class AssayRule:
    # Ruletypes!
    CLASSIFICATION = 1
    AS             = 2
    AS_IN_PATH     = 3
    DNS_NAME       = 4
    
    classtypes = [CLASSIFICATION, AS, AS_IN_PATH, DNS_NAME]
    global SERIAL

    def __init__(self, ruletype, value):
        logging.getLogger('netassay.AssayRule').info("AssayRule.__init__(): called")
        self.logger = logging.getLogger('netassay.AssayRule')
        self.type = ruletype
        self.value = value
        self.update_callbacks = []
        self.rule_limiter = RuleLimiter.get_instance()

        self.logger.debug("   self.type  = " + str(ruletype))
        self.logger.debug("   self.value = " + str(value))

        # Rules should be proper pyretic rules
        # _raw_xxx_rules is the naive set of rules that are manipulated. When 
        # self.get_list_of_rules() is called, self._rule_list is populated 
        # without any redundant rules.
        # The _rule_list is composed in parallel to get the policy of this rule
        # This allows for FAR easier manipulation of the rules that are active.
        self._raw_srcmac_rules = []
        self._raw_dstmac_rules = []
        self._raw_srcip_rules = []
        self._raw_dstip_rules = []
        self._raw_srcport_rules = []
        self._raw_dstport_rules = []
        self._raw_protocol_rules = []
        self._raw_other_rules = []
        self._rule_list = []

        # Timer and timer related - one timer for both add and remove
        self._timer = None
        self._rules_to_add = []
        self._rules_to_remove = []

    def number_of_rules(self):
        return (len(self._raw_srcmac_rules) +
                len(self._raw_dstmac_rules) +
                len(self._raw_srcip_rules) +
                len(self._raw_dstip_rules) + 
                len(self._raw_srcport_rules) +
                len(self._raw_dstport_rules) +
                len(self._raw_protocol_rules) +
                len(self._raw_other_rules))
    

    def set_update_callback(self, cb):
        # These callbacks take an AssayRule as input
        self.update_callbacks.append(cb)

    def _rule_timer(self):
        self.logger.debug("_rule_timer() called, addsize: " + str(len(self._rules_to_add)))
        self.logger.debug("                  lremovesize: " + str(len(self._rules_to_remove)))
#        self.logger.debug("    _rules_to_add:    " + str(self._rules_to_add))
#        self.logger.debug("    _rules_to_remove: " + str(self._rules_to_remove))

        total_rules_changed = len(self._rules_to_add) + len(self._rules_to_remove)


        # Stop the running delay timer
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

        for rule in self._rules_to_add:
            self.logger.debug("  Adding   " + str(rule))
            self._install_rule(rule)
        for rule in self._rules_to_remove:
            self.logger.debug("  Removing " + str(rule))
            self._uninstall_rule(rule)
        self._rules_to_add = []
        self._rules_to_remove = []
        self._update_rules()
        
    def add_rule_group(self, newrule):

        #FOR EVAL
        serial = serial_logging.get_number()
        logging.getLogger("netassay.evaluation2").info("ADD_RULE " + str(serial))
        logging.getLogger("netassay.evaluation2").info("NO_DELAY " + str(serial))

        self._rules_to_add.append({'rule':newrule, 'serial':serial})

    def finish_rule_group(self):
        # we want the same behaviour as _rule_timer, so call it directly.
        self._rule_timer()
    

    def add_rule(self, newrule):
        self.logger.debug("add_rule: timer - " + str(self._timer))

        #FOR EVAL
        serial = serial_logging.get_number()
        logging.getLogger("netassay.evaluation2").info("ADD_RULE " + str(serial))



        delay = self.rule_limiter.get_delay()
        if (delay == 0):
#            self._install_rule(newrule)
            logging.getLogger("netassay.evaluation2").info("NO_DELAY " + 
                                                           str(serial))
            self._install_rule({'rule':newrule, 'serial':serial})
            self._update_rules()
            self.logger.debug("    nodelay == True")

        else:
            logging.getLogger("netassay.evaluation2").info("WITH_DELAY " + 
                                                           str(serial))
#            self._rules_to_add.append(newrule)
            self._rules_to_add.append({'rule':newrule, 'serial':serial})
#            self.logger.debug("    new rule: " + str(newrule))
#            self.logger.debug("    rules in queue: " + str(self._rules_to_add))
            if self._timer is None:
                self._timer = Timer(TIMEOUT, self._rule_timer)
                self._timer.start()
                self.logger.debug("    new timer   - " + str(self._timer))

    def _install_rule(self, newrule):
        # Does not check to see if it's a duplicate rule, as this allows the 
        # same rule to be installed for different reasons, and they can be 
        # removed individually.
        logging.getLogger("netassay.evaluation2").info("INSTALL_RULE " + 
                                                       str(newrule['serial']))
        if isinstance(newrule['rule'], Match):
            #FIXME: Can this optimize over multiple items?
            if len(newrule['rule'].map.keys()) == 1:
                key = newrule['rule'].map.keys()[0] # get the key of the only value
                if (key == 'srcmac'):
                    self._raw_srcmac_rules.append(newrule)
                elif (key == 'dstmac'):
                    self._raw_dstmac_rules.append(newrule)
                elif (key == 'srcport'):
                    self._raw_srcport_rules.append(newrule)
                elif (key == 'dstport'):
                    self._raw_dstport_rules.append(newrule)
                elif (key == 'srcip'):
                    self._raw_srcip_rules.append(newrule)
                elif (key == 'dstip'):
                    self._raw_dstip_rules.append(newrule)
                elif (key == 'protocol'):
                    self._raw_protocol_rules.append(newrule)
                else:
                    self._raw_other_rules.append(newrule)
            else:
                self._raw_other_rules.append(newrule)
        else:
            self._raw_other_rules.append(newrule)


#    def has_rule(self, newrule):
#        return ((newrule in self._raw_srcip_rules) |
#                (newrule in self._raw_dstip_rules) |
#                (newrule in self._raw_srcmac_rules) |
#                (newrule in self._raw_dstmac_rules) |
#                (newrule in self._raw_srcport_rules) |
#                (newrule in self._raw_dstport_rules) |
#                (newrule in self._raw_protocol_rules) |
#                (newrule in self._raw_other_rules))

    def remove_rule(self, newrule):
        self.logger.debug("remove_rule: timer - " + str(self._timer))

        #FOR EVAL
        serial = serial_logging.get_number()
        logging.getLogger("netassay.evaluation2").info("REMOVE_RULE " + 
                                                       str(serial))

        delay = self.rule_limiter.get_delay()
        if (0 == delay):
#            self._uninstall_rule(newrule)
            logging.getLogger("netassay.evaluation2").info("NO_DELAY " + 
                                                           str(serial))
            self._uninstall_rule({'rule':newrule, 'serial':serial})
            self._update_rules()
            self.logger.debug("    nodelay == True")

        else:
            logging.getLogger("netassay.evaluation2").info("WITH_DELAY" + 
                                                           str(serial))
#            self._rules_to_remove.append(newrule)
            self._rules_to_remove.append({'rule':newrule, 'serial':serial})
#            self.logger.debug("    new rule: " + str(newrule))
#            self.logger.debug("    rules in queue: " + str(self._rules_to_remove))
            if self._timer is None:
                self._timer = Timer(TIMEOUT, self._rule_timer)
                self._timer.start()
                self.logger.debug("    new timer   - " + str(self._timer))

    def _uninstall_rule(self, newrule):
        # In expected order of being true. Please rearrange as appropriate.
        
        # Thanks to: https://stackoverflow.com/questions/8653516/python-list-of-dictionaries-search
        logging.getLogger("netassay.evaluation2").info("UNINSTALL_RULE" + 
                                                       str(newrule['serial']))
        if filter(lambda rule: rule['rule'] == newrule, 
                  self._raw_srcip_rules) != []:
            self._raw_srcip_rules.remove(
                filter(lambda rule: rule['rule'] == newrule, 
                       self._raw_srcip_rules))
        if filter(lambda rule: rule['rule'] == newrule, 
                  self._raw_dstip_rules) != []:
            self._raw_dstip_rules.remove(
                filter(lambda rule: rule['rule'] == newrule, 
                       self._raw_dstip_rules))
        if filter(lambda rule: rule['rule'] == newrule, 
                  self._raw_srcmac_rules) != []:
            self._raw_srcmac_rules.remove(
                filter(lambda rule: rule['rule'] == newrule, 
                       self._raw_srcmac_rules))
        if filter(lambda rule: rule['rule'] == newrule, 
                  self._raw_dstmac_rules) != []:
            self._raw_dstmac_rules.remove(
                filter(lambda rule: rule['rule'] == newrule, 
                       self._raw_dstmac_rules))
        if filter(lambda rule: rule['rule'] == newrule, 
                  self._raw_srcport_rules) != []:
            self._raw_srcport_rules.remove(
                filter(lambda rule: rule['rule'] == newrule, 
                       self._raw_srcport_rules))
        if filter(lambda rule: rule['rule'] == newrule, 
                  self._raw_dstport_rules) != []:
            self._raw_dstport_rules.remove(
                filter(lambda rule: rule['rule'] == newrule, 
                       self._raw_dstport_rules))
        if filter(lambda rule: rule['rule'] == newrule, 
                  self._raw_protocol_rules) != []:
            self._raw_protocol_rules.remove(
                filter(lambda rule: rule['rule'] == newrule, 
                       self._raw_protocol_rules))
        if filter(lambda rule: rule['rule'] == newrule, 
                  self._raw_other_rules) != []:
            self._raw_other_rules.remove(
                filter(lambda rule: rule['rule'] == newrule, 
                       self._raw_other_rules))

#        if newrule in self._raw_srcip_rules:
#            self._raw_srcip_rules.remove(newrule)
#        elif newrule in self._raw_dstip_rules:
#            self._raw_dstip_rules.remove(newrule)
#        elif newrule in self._raw_srcmac_rules:
#            self._raw_srcmac_rules.remove(newrule)
#        elif newrule in self._raw_dstmac_rules:
#            self._raw_dstmac_rules.remove(newrule)
#        elif newrule in self._raw_srcport_rules:
#            self._raw_srcport_rules.remove(newrule)
#        elif newrule in self._raw_dstport_rules:
#            self._raw_dstport_rules.remove(newrule)
#        elif newrule in self._raw_protocol_rules:
#            self._raw_protocol_rules.remove(newrule)
#        elif newrule in self._raw_other_rules:
#            self._raw_other_rules.remove(newrule)


    def _update_rules(self):
        self.logger.debug("_update_rules() called")
        logging.getLogger("netassay.evaluation2").info("UPDATE_RULES")

        # check if rules have changed
        temp_rule_list = self._generate_list_of_rules()
        # If they're the same, do nothing
        if set(temp_rule_list) == set(self._rule_list):
            self.logger.debug("_update_rules: No changes in rule list")
            logging.getLogger("netassay.evaluation2").info("NO_RULES_TO_ADD " + 
                                                           str(len(self._rule_list)) + " " +
                                                           str(self.number_of_rules()))
        else:
            # if they're different, call the callbacks
            self._rule_list = temp_rule_list
            logging.getLogger("netassay.evaluation2").info("RULES_TO_ADD " + 
                                                           str(len(self._rule_list)) + " " +
                                                           str(self.number_of_rules()))

            for cb in self.update_callbacks:
                self.logger.debug("_update_rules: calling " + str(cb))
                cb()
        logging.getLogger("netassay.evaluation2").info("UPDATE_RULES_FINISHED")


    def _generate_list_of_rules(self):
        # This generates the list of rules and returns them This allows us
        # to check to see if there's a difference between versions
        temp_rule_list = []


        # Optimized rules 
        # ipaddr documentation: https://code.google.com/p/ipaddr-py/wiki/Using3144
        def optimize_ip(rule_list, ip_rule_list_of_dicts, src_or_dst):
            to_remove_list = []
            ip_rule_list = []
            for ruledict in ip_rule_list_of_dicts:
                ip_rule_list.append(ruledict['rule'])

            temp_ip_rules = sorted(ip_rule_list, key=lambda ad: ad.map[src_or_dst].prefixlen)
            for rule in temp_ip_rules:
                # +1 is to skip the current rule...
                for interior_rule in temp_ip_rules[temp_ip_rules.index(rule)+1:]:
                    if interior_rule.map[src_or_dst] in rule.map[src_or_dst]:
                        to_remove_list.append(interior_rule)
                        break

            for rule in to_remove_list:
                temp_ip_rules.remove(rule)

            for rule in temp_ip_rules:
                if rule not in rule_list:
                    rule_list.append(rule)

        # This is a replacement for optimize_ip(), but I'm leaving the other
        # just in case the old one is faster.
        def optimize_ip_prefix(rule_list, ip_rule_list_of_dicts, src_or_dst):
            prefix_list = []
            ip_rule_list = []
            for ruledict in ip_rule_list_of_dicts:
                ip_rule_list.append(ruledict['rule'])

            for rule in ip_rule_list:
                prefix_list.append(rule.map[src_or_dst])

            for prefix in CollapseAddrList(prefix_list):
                rule_list.append(Match({src_or_dst: prefix}))           

        # These are the initial installation of rules that have basic 
        # de-duplication, but nothing else. The optimized functions below are
        # much better.
#        for rule in self._raw_srcip_rules:
#            if rule not in temp_rule_list:
#                temp_rule_list.append(rule)
#        for rule in self._raw_dstip_rules:
#            if rule not in temp_rule_list:
#                temp_rule_list.append(rule)
#        for rule in self._raw_other_rules:
#            if rule not in temp_rule_list:
#                temp_rule_list.append(rule)
            
        # optimize_ip() was an initial pass at manually optimizing IP rules.
        # optimize_ip_prefix() uses the functions in ipaddr-py package. Cleaner.
#        optimize_ip(temp_rule_list, self._raw_srcip_rules, 'srcip')
#        optimize_ip(temp_rule_list, self._raw_dstip_rules, 'dstip')

        # Optimizing others - function may be useful outside of here.
        def optimize_others(rule_list, other_rule_list):
            headers =  ['srcmac','dstmac','srcport','dstport',
                        'ethtype','protocol','tos']
            ips = ['srcip','dstip']

            temp_other_rules = list(other_rule_list)

            # Separate out the IP related rules
            temp_srcip_rules = []
            temp_dstip_rules = []
            to_remove_list = []

            # First pass is pretty easy, doesn't handle IP addresses
            for rule in temp_other_rules:
                for header in headers:
                    if header in rule.map.keys():
                        to_check = Match({header : rule.map[header]})
                        if to_check in rule_list:
                            to_remove_list.append(rule)
                            break
            for rule in to_remove_list:
                temp_other_rules.remove(rule)


            # Second pass handles IPs. These are different, only because they
            # can easily be subsumed by prefixes.
            for rule in temp_other_rules:
                if 'srcip' in rule.map.keys():
                    temp_srcip_rules.append(rule)
                elif 'dstip' in rule.map.keys():
                    temp_srcip_rules.append(rule)
            for rule in temp_srcip_rules:
                temp_other_rules.remove(rule)
            for rule in temp_dstip_rules:
                temp_other_rules.remove(rule)


            temp_srcip_rules = sorted(temp_srcip_rules, key=lambda ad: ad.map['srcip'].prefixlen)
            temp_dstip_rules = sorted(temp_dstip_rules, key=lambda ad: ad.map['dstip'].prefixlen)

            to_remove_list = []
            for rule in temp_srcip_rules:
                for existing_rule in rule_list:
                    if 'srcip' in existing_rule.map.keys():
                        if rule.map['srcip'] in existing_rule.map['srcip']:
                            to_remove_list.append(rule)
                            break

            for rule in to_remove_list:
                temp_srcip_rules.remove(rule)

            to_remove_list = []
            for rule in temp_dstip_rules:
                for existing_rule in rule_list:
                    if 'dstip' in existing_rule.map.keys():
                        if rule.map['dstip'] in existing_rule.map['dstip']:
                            to_remove_list.append(rule)
                            break
            for rule in to_remove_list:
                temp_dstip_rules.remove(rule)



            for rule in temp_other_rules:
                if rule not in rule_list:
                    rule_list.append(rule)
            for rule in temp_srcip_rules:
                if rule not in rule_list:
                    rule_list.append(rule)
            for rule in temp_dstip_rules:
                if rule not in rule_list:
                    rule_list.append(rule)

        # Append non-optimized rules, remove dupes
        def dedupe_non_optimized(temp_rule_list):
            for ruledict in self._raw_protocol_rules:
                rule = ruledict['rule']
                if rule not in temp_rule_list:
                    temp_rule_list.append(rule)
            for ruledict in self._raw_srcmac_rules:
                rule = ruledict['rule']
                if rule not in temp_rule_list:
                    temp_rule_list.append(rule)
            for ruledict in self._raw_dstmac_rules:
                rule = ruledict['rule']
                if rule not in temp_rule_list:
                    temp_rule_list.append(rule)
            for ruledict in self._raw_srcport_rules:
                rule = ruledict['rule']
                if rule not in temp_rule_list:
                    temp_rule_list.append(rule)
            for ruledict in self._raw_dstport_rules:
                rule = ruledict['rule']
                if rule not in temp_rule_list:
                    temp_rule_list.append(rule)

        def only_dedupe(temp_rule_list):
            for ruledict in self._raw_srcip_rules:
                rule = ruledict['rule']
                if rule not in temp_rule_list:
                    temp_rule_list.append(rule)
            for ruledict in self._raw_dstip_rules:
                rule = ruledict['rule']
                if rule not in temp_rule_list:
                    temp_rule_list.append(rule)
            for ruledict in self._raw_other_rules:
                rule = ruledict['rule']
                if rule not in temp_rule_list:
                    temp_rule_list.append(rule)

        def completely_unoptimized(temp_rule_list):
            for ruledict in self._raw_protocol_rules:
                rule = ruledict['rule']
                temp_rule_list.append(rule)
            for ruledict in self._raw_srcmac_rules:
                rule = ruledict['rule']
                temp_rule_list.append(rule)
            for ruledict in self._raw_dstmac_rules:
                rule = ruledict['rule']
                temp_rule_list.append(rule)
            for ruledict in self._raw_srcport_rules:
                rule = ruledict['rule']
                temp_rule_list.append(rule)
            for ruledict in self._raw_dstport_rules:
                rule = ruledict['rule']
                temp_rule_list.append(rule)
            for ruledict in self._raw_srcip_rules:
                rule = ruledict['rule']
                temp_rule_list.append(rule)
            for ruledict in self._raw_dstip_rules:
                rule = ruledict['rule']
                temp_rule_list.append(rule)
            for ruledict in self._raw_other_rules:
                rule = ruledict['rule']
                temp_rule_list.append(rule)


# with-optimizations        
        optimize_ip_prefix(temp_rule_list, self._raw_srcip_rules, 'srcip')
        optimize_ip_prefix(temp_rule_list, self._raw_dstip_rules, 'dstip')
        optimize_others(temp_rule_list, self._raw_other_rules)

# prefix-optimizations-only
#        optimize_ip_prefix(temp_rule_list, self._raw_srcip_rules, 'srcip')
#        optimize_ip_prefix(temp_rule_list, self._raw_dstip_rules, 'dstip')

# dedupe-only
#        dedupe_non_optimized(temp_rule_list)
#        only_dedupe(temp_rule_list)

# no-optimizations
#        completely_unoptimized(temp_rule_list)

        return temp_rule_list

    def get_list_of_rules(self):
        self._rule_list = self._generate_list_of_rules()
        return self._rule_list




    def _display_for_testing(self):
        if len(self._raw_srcmac_rules) > 0:
            print "_raw_srcmac_rules:"
            for rule in self._raw_srcmac_rules:
                print "    " + str(rule)
            print ""
        
        if len(self._raw_dstmac_rules) > 0:
            print "_raw_dstmac_rules:"
            for rule in self._raw_dstmac_rules:
                print "    " + str(rule)
            print ""

        if len(self._raw_srcip_rules) > 0:
            print "_raw_srcip_rules:"
            for rule in self._raw_srcip_rules:
                print "    " + str(rule)
            print ""
        
        if len(self._raw_dstip_rules) > 0:
            print "_raw_dstip_rules:"
            for rule in self._raw_dstip_rules:
                print "    " + str(rule)
            print ""

        if len(self._raw_srcport_rules) > 0:
            print "_raw_srcport_rules:"
            for rule in self._raw_srcport_rules:
                print "    " + str(rule)
            print ""
        
        if len(self._raw_dstport_rules) > 0:
            print "_raw_dstport_rules:"
            for rule in self._raw_dstport_rules:
                print "    " + str(rule)
            print ""

        if len(self._raw_protocol_rules) > 0:
            print "_raw_protocol_rules:"
            for rule in self._raw_protocol_rules:
                print "    " + str(rule)
            print ""

        if len(self._raw_other_rules) > 0:
            print "_raw_other_rules:"
            for rule in self._raw_other_rules:
                print "    " + str(rule)
            print ""

        if len(self._rule_list) > 0:
            print "_rule_list"
            for rule in self._rule_list:
                print "    " + str(rule)
            print ""

# Unit tests to verify that optimizations do, in fact, work.
if __name__ == "__main__":
    
    from pyretic.core.network import IPAddr

    # Remove duplicates test
    dupe = AssayRule(AssayRule.DNS_NAME, 'dummy')
    dupe.add_rule(Match(dict(srcip=IPAddr("1.2.3.4"))))
    dupe.add_rule(Match(dict(srcip=IPAddr("1.2.3.4"))))
    dupe.add_rule(Match(dict(dstip=IPAddr("1.2.3.4"))))
    dupe.add_rule(Match(dict(srcmac="aa:bb:cc:dd:ee:ff")))
    dupe.add_rule(Match(dict(srcmac="aa:bb:cc:dd:ee:ff")))


    print "DUPLICATES TEST BEGIN"
    dupe._display_for_testing()
    print "DUPLICATES TEST END"
    print ""
    
    # IP Optimization
    optimization = AssayRule(AssayRule.DNS_NAME, 'dummy')
    optimization.add_rule(Match(dict(srcip=IPAddr("1.2.3.4"))))
    optimization.add_rule(Match(dict(srcip=IPv4Network("1.2.3.0/24"))))

    optimization.add_rule(Match(dict(srcip=IPv4Network("2.3.4.0/24"))))
    optimization.add_rule(Match(dict(srcip=IPv4Network("2.3.0.0/16"))))

    optimization.add_rule(Match(dict(srcip=IPv4Network("3.2.0.0/16"))))
    optimization.add_rule(Match(dict(srcip=IPv4Network("3.3.0.0/16"))))

    optimization.add_rule(Match(dict(srcip=IPv4Network("4.2.0.0/16"))))
    optimization.add_rule(Match(dict(srcip=IPv4Network("4.3.0.0/16"))))
    optimization.add_rule(Match(dict(srcip=IPv4Network("4.3.4.0/24"))))


    print "IP OPTIMIZATION TEST BEGIN"
    optimization._display_for_testing()
    print "IP OPTIMIZATION TEST END"
    print ""


    # Others optimization
    others = AssayRule(AssayRule.DNS_NAME, 'dummy')
    others.add_rule(Match(dict(srcip=IPAddr("1.2.3.4"))))
    others.add_rule(Match(dict(srcip=IPAddr("1.2.3.4"),srcport='1234')))

    others.add_rule(Match(dict(srcip=IPAddr("2.3.4.5"))))
    others.add_rule(Match(dict(srcport='2345')))
    others.add_rule(Match(dict(srcip=IPAddr("2.3.4.5"),srcport='2345')))

    others.add_rule(Match(dict(srcip=IPv4Network("3.4.5.0/16"))))
    others.add_rule(Match(dict(srcip=IPAddr("3.4.5.6"),srcport='2345')))


    print "OTHERS OPTIMIZATION TEST BEGIN"
    others._display_for_testing()
    print "OTHERS OPTIMIZATION TEST END"
