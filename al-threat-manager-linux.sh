#!/bin/bash

THREATAL_i386="al-threat-host_LATEST.i386.rpm"
THREATAL_x86_64="al-threat-host_LATEST.x86_64.rpm"
DEBIANTHREATAL_i386="al-threat-host_LATEST.i386.deb"
DEBIANTHREATAL_x86_64="al-threat-host_LATEST.x86_64.deb"
SRC_DIR="../Downloads/"
DST_DIR="."
#Defaults for testing
KEY=""
HOST=""
VERBOSE=false

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 
fi

while getopts "H:k:v" opt; do
    case "$opt" in
        H)
            HOST=$OPTARG
            ;;
        k)
            KEY=$OPTARG
            ;;
        v)
            VERBOSE=true
            ;;
    esac
done

if $VERBOSE ; then
    echo "Gathering OS information." 
fi

if [ `getconf LONG_BIT` = "32" ]
then
    if [ -f /etc/redhat-release ]; then
        COMMANDS[0]="rpm -ivh $THREATAL_i386"
        COMMANDS[1]="/etc/init.d/al-threat-host provision -H $HOST --key $KEY"
        COMMANDS[2]="/etc/init.d/al-threat-host start"
        if $VERBOSE ; then
            echo "32 bit package RHEL installation" 
        fi
    elif [ -f /etc/debian_version ]; then
        COMMANDS[0]="dpkg -i $DEBIANTHREATAL_i386"
        COMMANDS[1]="/etc/init.d/al-threat-host configure --host $HOST"
        COMMANDS[2]="/etc/init.d/al-threat-host provision --key $KEY"
        COMMANDS[3]="/etc/init.d/al-threat-host start"
        if $VERBOSE ; then
            echo "32 bit package Debian installation" 
        fi
    else
        echo "Uknown linux distro."
        exit
    fi
else
    if [ -f /etc/redhat-release ]; then
        COMMANDS[0]="rpm -ivh $THREATAL_x86_64"
        COMMANDS[1]="/etc/init.d/al-threat-host provision -H $HOST --key $KEY"
        COMMANDS[2]="/etc/init.d/al-threat-host start"
        if $VERBOSE ; then
            echo "64 bit package RHEL installation" 
        fi
    elif [ -f /etc/debian_version ]; then
        COMMANDS[0]="dpkg -i $DEBIANTHREATAL_x86_64"
        COMMANDS[1]="/etc/init.d/al-threat-host configure --host $HOST"
        COMMANDS[2]="/etc/init.d/al-threat-host provision --key $KEY"
        COMMANDS[3]="/etc/init.d/al-threat-host start"
        if $VERBOSE ; then
            echo "64 bit package Debian installation" 
        fi
    else
        echo "Uknown linux distro."
        exit
    fi
fi

rsync $SRC_DIR$PACKAGE_NAME $DST_DIR
if $VERBOSE ; then
    echo "Installing package: " $PACKAGE_NAME 
fi
if $VERBOSE ; then
    echo "Configuring threat host with: " $HOST $KEY 
fi
# Call the commands
for ((i=0; i<${#COMMANDS[@]}; ++i))
do
    eval ${COMMANDS[$i]}
done

