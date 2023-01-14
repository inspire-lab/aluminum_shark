#!/bin/bash

# runs the program and argugments using gdb
gdb -ex=r --args "$@"
