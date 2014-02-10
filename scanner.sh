#!/bin/bash

HOST="localhost"
PORT=""

function check_root {
    if [ "$(id -u)" != "0" ]; then
        echo "Got root?"
        exit
    fi
}

function scan {
    for a in $(yes scan | head -1024)
    do
        (( ++start ))
        if [[ -n $(echo '' > /dev/$2/$1/$start && echo "up") ]];
            then
            echo "Port $start" >> scan;
        fi
    done
}

function display_help {
    echo "Usage: scan -H {hostname} -p {port}" 
    exit
}  

check_root
while getopts "H:p:h" opt; do
    case "$opt" in
        H)
            HOST=$OPTARG
            ;;
        p)
            PORT=$OPTARG
            ;;
        h)
            echo "displaying help!"
            display_help
            ;;
    esac
done
scan
