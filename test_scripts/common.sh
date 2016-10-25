#!/bin/bash

mkdir -p ./out
rm -f ./out/*.log

debug=""

if [ "$1" == '-d' ]; then
    debug=-d
fi

s=0
p=0
rS=0
rP=0

function reg_subs {
    rS=$((rS+1))
    f=./out/reg_subs$rS.log
    sleep 0.1
    echo -e "=============================\nreg_subs$rS $debug $@" | tee $f
    echo "==============================" >> $f
    build/dist/bin/reg_subs $debug $@ 2>> $f &
}

function reg_pubs {
    rP=$((rP+1))
    f=./out/reg_pubs$rP.log
    sleep 0.1
    echo -e "=============================\nreg_pubs$rP $debug $@" | tee $f
    echo "==============================" >> $f
    build/dist/bin/reg_pubs $debug $@ 2>> $f &
}

function sub {
    s=$((s+1))
    f=./out/sub$s.log
    sleep 0.1
    echo -e "=============================\nsub$s $debug $@" | tee $f
    echo "==============================" >> $f
    build/dist/bin/subscriber $debug $@ 2>> $f &
}

function pub {
    p=$((p+1))
    f=./out/pub$p.log
    sleep 0.1
    echo -e "=============================\npub$p $debug $@" | tee $f
    echo "==============================" >> $f
    msg=$(echo "Published topics: " $@)
    build/dist/bin/publisher $debug $@ -m "$msg" 2>> $f &
}

function cleanup {
    killall -w reg_subs
    killall -w reg_pubs
    killall -w subscriber
    killall -w publisher
}
