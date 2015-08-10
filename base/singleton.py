#########################
# NetAssay Project
#########################

# Copyright 2015 - Sean Donovan


# Definition of a singleton. This is used heavily by NetAssay.
# Based on https://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
