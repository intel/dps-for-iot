#!/bin/bash

PYTHONPATH=./build/dist/py
NODE_PATH=./build/dist/js
export PYTHONPATH NODE_PATH

function reset_logs {
    mkdir -p ./out
    rm -f ./out/*.log
}
reset_logs

debug=""
subsRate="-r 100"

if [ "$1" == '-d' ]; then
    debug=-d
fi

s=0
p=0
v=0
n_=0
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
    echo -e "=============================\nsub$s $debug $subsRate $@" | tee $f
    echo "==============================" >> $f
    build/dist/bin/subscriber $debug $subsRate $@ 2>> $f &
}

function pub {
    p=$((p+1))
    f=./out/pub$p.log
    sleep 0.1
    echo -e "=============================\npub$p $debug $subsRate $@" | tee $f
    echo "==============================" >> $f
    # topic data (msg) is a string listing the topics
    args="$*"
    msg=$(echo "Published topics: ${args[@]//-* /}")
    build/dist/bin/publisher $debug -w 1 $subsRate $@ -m "$msg" 2>> $f &
}

function ver {
    v=$((v+1))
    f=./out/ver$v.log
    sleep 0.1
    echo -e "=============================\nver$v $debug $@" | tee $f
    echo "==============================" >> $f
    build/test/bin/version $debug $@ 2>> $f &
}

function test_node {
    n_=$((n_+1))
    f=./out/node$n_.log
    sleep 0.1
    echo -e "=============================\nnode$n_ $debug $@" | tee $f
    echo "==============================" >> $f
    build/test/bin/node $debug $@ 2>> $f &
}

function py_sub {
    s=$((s+1))
    f=./out/sub$s.log
    sleep 0.1
    echo -e "=============================\nsub$s $@" | tee $f
    echo "==============================" >> $f
    python -u ./py_scripts/simple_sub.py $@ 2>> $f 1>&2 &
}

function py_late_sub {
    s=$((s+1))
    f=./out/sub$s.log
    sleep 0.1
    echo -e "=============================\nsub$s" | tee $f
    echo "==============================" >> $f
    python -u ./py_scripts/late_sub.py 2>> $f 1>&2 &
}

function py_pub {
    p=$((p+1))
    f=./out/pub$p.log
    sleep 0.1
    echo -e "=============================\npub$p $@" | tee $f
    echo "==============================" >> $f
    python -u ./py_scripts/simple_pub.py $@ 2>> $f 1>&2 &
}

function py_retained_pub {
    p=$((p+1))
    f=./out/pub$p.log
    sleep 0.1
    echo -e "=============================\npub$p" | tee $f
    echo "==============================" >> $f
    python -u ./py_scripts/retained_pub.py 2>> $f 1>&2 &
}

function js_sub {
    s=$((s+1))
    f=./out/sub$s.log
    sleep 0.1
    echo -e "=============================\nsub$s $@" | tee $f
    echo "==============================" >> $f
    node ./js_scripts/simple_sub.js $@ 2>> $f 1>&2 &
}

function js_pub {
    p=$((p+1))
    f=./out/pub$p.log
    sleep 0.1
    echo -e "=============================\npub$p $@" | tee $f
    echo "==============================" >> $f
    node ./js_scripts/simple_pub.js $@ 2>> $f 1>&2 &
}

function assert_no_errors {
    n=$(grep -s -ir "ERROR" out | wc -l)
    if [ $n -gt 0 ]; then
        echo "Errors $n"
        grep -s -iHr "ERROR" out
        exit 1
    fi
}

# expect_pubs_received N TOPIC [TOPIC...]
function expect_pubs_received {
    expected=$1
    shift
    topics=$*
    topics=${topics// / | }
    n=$(grep -s "pub $topics\$" out/{sub,node}*.log | wc -l)
    if [ $n -ne $expected ]; then
        echo "Pubs ($topics) received is not equal to expected ($n != $expected)"
        grep -s "pub $topics\$" out/sub*.log
        exit 1
    fi
}

# expect_acks_received N
function expect_acks_received {
    expected=$1
    n=$(grep -s "Ack for pub" out/pub*.log | wc -l)
    if [ $n -ne $expected ]; then
        echo "Acks received is not equal to expected ($n != $expected)"
        grep -s "Ack for pub" out/pub*.log
        exit 1
    fi
}

# expect_errors N ERROR
function expect_errors {
    n=$(grep -s -r "ERROR.*$2" out | wc -l)
    if [ $n -lt $1 ]; then
        echo "Errors found is less than expected ($n != $1)"
        exit 1
    fi
}

function cleanup {
    kill $(jobs -rp)
    wait $(jobs -rp) 2>/dev/null
}
trap cleanup EXIT
