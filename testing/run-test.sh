#!/bin/bash

# Copyright 2015 - Sean Donovan
# NetAssay Project

if [ -z $1 ]; then
    echo "Usage run-test.sh <config file>"
    exit
fi

PYTHONPATH=/home/mininet/pyretic:/home/mininet/mininet:/home/mininet/pox:/home/mininet/ryu:/home/mininet/netassay-ryu

pushd ~/ryu
./bin/ryu-manager --verbose $1
popd
