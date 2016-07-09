#!/bin/bash

mkdir -p ./out
rm -f ./out/*.log

debug=""

if [ "$1" == '-d' ]; then
    debug=-d
fi

s=0
p=0

function sub {
    s=$((s+1))
    f=./out/sub$s.log
    sleep 0.1
    echo -e "=============================\nsub$s $debug $@" | tee $f
    echo "==============================" >> $f
    ../bin/subscriber $debug $@ 2>> $f &
}

function pub {
    p=$((p+1))
    f=./out/pub$p.log
    sleep 0.1
    echo -e "=============================\npub$s $debug $@" | tee $f
    echo "==============================" >> $f
    ../bin/publisher $debug $@ 2>> $f &
}

function cleanup {
    killall -w subscriber
    killall -w publisher
}
