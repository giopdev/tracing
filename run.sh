#!/bin/bash

if [[ "$1" == "1" ]]; then
    sudo ./triangleTrace.py ./src/main.bin ./src/main.cpp main.bin intel
else
    sudo ./triangleTrace.py ./src/main.bin ./src/main.cpp main.bin amd
fi
