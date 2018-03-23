#!/bin/sh

#python  ./lfidriver/gendriver.py -d kernels
#cp os.pyh lfidriver
python  ./lfidriver/gendriver.py lfidriver/os.pyh > lfidriver/driver/monitor_gen.c

