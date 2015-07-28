#########################
# NetAssay Project
#########################

# Copyright 2015 - Sean Donovan
# Copyright 2014 - Sean Donovan
# MetadataEngine parent class, MetadataEntries parent class
# 
# Based on the Pyretic-based NetAssay, updated for NetAssay-ryu project.

import logging
from singleton import Singleton


class MetadataEngineException(Exception):
    pass

class MetadataEngine(object):
    __metaclass__ = Singleton
    """
    Definition of the MetadataEngine parent class. All MEs should inherit
    from here.
    MEs are singletons.
    """
    def __init__(self, data_source, metadata_entry_type):
        """
        Initializes the parent MetadataEngine class. This should be called before
        anything else. Child classes will need to set up a few more things:
          - Call RegisteredMatchActions.register() for whatever they are able
            to match on. 

        """

        # Setup logging
        loggername = "netassay." + self.__class__.__name__
        logging.getLogger(loggername).info("__init__(): called")
        self.logger = logging.getLogger(loggername)

        # Initialize the list of MetadataEntrys
        self.entries = []
#TODO?
        self.entry_type = metadata_entry_type

        # Save off the data source that is used by the MetadataEntrys
        self.data_source = data_source

    def get_forwarding_rule(self):
        """
        This gets the default forwarding rules. If there are no forwarding rules,
        then this need not be defined in the subclasses. 

        By default, return identity, so that it can be ignored. returning drop
        could actually drop traffic.
        """
#TODO
        self.logger.info("get_forwarding_rules(): called")
        return identity

    def new_rule(self, rule):
        """
        This kicks off the new rule process that is handled by MetadataEntries.
        See their definition below.
        The rule parameter is simply for tracking. It is not used in this 
        version.
        """
        self.logger.info("new_rule(): called")
        #TODO
        self.entries.append(self.entry_type(self.data_source, self, rule))





class MetadataEntry(object):
    def __init__(self, data_source, engine, rule):
        """
        Initializes the parent MetadataEntry class. This should be called before
        and child-initialization happens. Child classes will need to set up a few
        more things:
          - Register for any ME specific callbacks and handers, such a new
            information coming in.
          - Set up any initial rules that are needed, say from a configuration
            file.
        """
        loggername = "netassay." + self.__class__.__name__
        logging.getLogger(loggername).info("__init__(): called")
        self.logger = logging.getLogger(loggername)
        self.data_source = data_source
        self.engine = engine
        self.rule = rule

        # These callbacks are used when new rules need to be added
        self.add_rule_cb = None
        self.remove_rule_cb = None

    def register_callbacks(self, add_rule_cb, remove_rule_cb):
        self.add_rule_cb = add_rule_cb
        self.remove_rule_cb = remove_rule_cb
    
