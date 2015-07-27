#########################
# NetAssay Project
#########################

# Copyright 2015 - Sean Donovan


import logging

from singleton import Singleton

class RegisteredMatchActionsException(Exception):
    pass

# This is used by MEs to register the different match values they wish to
# receive. They call this during their __init__() function. 
# Based on previous work, located at:
# https://github.com/sdonovan1985/netassay/blob/master/pyretic/core/language.py#L1489
class RegisteredMatchActions(object):
    __metaclass__ = Singleton
    """
    The class that handles the particular attribute must take as its only 
    parameter in __init__ the value that it's being set to in the match class.

    Example:
       match(domain='example.com') 
    The handler for 'domain' matching, say matchDomain, would be initialized as
    follows:
       matchDomain('example.com')
    """

    _registered_matches = {}

    def register(self, attribute, handler):
        """
        Registers new classes to handle new attributes.
        attribute in the above example is 'domain'
        handler in the above example is the class matchDomain
        """
        self._registered_matches[attribute] = handler

    def lookup(self, attribute):
        if attribute not in self._registered_matches.keys():
            # This is normal. Everything that returns this should be handled by 
            # the Match class
            # FIXME - Is this always true?
            raise RegisteredMatchActionsException(
                str(attribute) + " not registered")
        return self._registered_matches[attribute]

    def exists(self, attribute):
        return (attribute in self._registered_matches.keys())


