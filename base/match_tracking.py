#########################
# NetAssay Project
#########################

# Copyright 2015 - Sean Donovan

# Definition of match_tracking. 
# Object is only used by NetAssayMatchAction and by the MCM. It is, in effect,
# a structure holding all of the properties.


class match_tracking(object):
    
    def __init__(self, submatch, postmatch, cookie, subactions, parent, vmac):
        self.submatch = submatch
        self.postmatch = postmatch
        self.cookie = cookie
        self.subactions = subactions
        self.parent = parent
        self.vmac = vmac
        self.count = 1
        self.ofpmatch = None



class match_tracking_collection(object):
    #TODO: Make this a Python collection?

    def __init__(self):
        self._dict = {}
    
    pass


    

        
    
