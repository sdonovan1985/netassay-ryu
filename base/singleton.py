#########################
# NetAssay Project
#########################

# Copyright 2015 - Sean Donovan


# Definition of a singleton. This is used heavily by NetAssay.
# Based on https://stackoverflow.com/questions/31875/is-there-a-simple-elegant-way-to-define-singletons-in-python

#class Singleton(object):
#    _instance = None
#
#    def __new__(cls, *args, **kwargs):
#        if not cls._instance:
#            cls._instance = super(Singleton, cls).__new__(
#                                cls, *args, **kwargs)
#        return cls._instance
    


#def singleton(cls):
#    instances = {}
#    def getinstance():
#        if cls not in instances:
#            instances[cls] = cls()
#        return instances[cls]
#    return getinstance

#def singleton(cls):
#    obj = cls()
#    # Always return the same object
#    cls.__new__ = staticmethod(lambda cls: obj)
#    # Disable __init__
#    try:
#        del cls.__init__
#    except AttributeError:
#        pass
#    return cls

# Based on https://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
