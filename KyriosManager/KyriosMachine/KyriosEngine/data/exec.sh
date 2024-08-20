#!/bin/bash
adb start-server 
emulator -avd Nexus_XL_API_30 -no-window -no-audio -no-snapshot-load -no-snapshot-save -gpu off -no-boot-anim -wipe-data -no-metrics
