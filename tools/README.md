# A repository for useful tools

## asan_addr2line

Applies addr2line to a fuzzer crash log.

`./build/test/bin/cbor_fuzzer ./crash-f15bb0b64b75838dc982cef11b0c3b9ea08fcec6 2>&1 | ./tools/asan_addr2line`

## corpus_pcap

Create a seed corpus for fuzzing from a tcpdump capture.

`corpus_pcap --dir ./corpus dps.pcapng`

Capture packets from a run of the tests:
```
$ tcpdump -i any -p -s 0 -w dps.tcpdump
$ ./test_scripts/run.py
```
Filter multicast DPS packets:
```
$ tshark -r dps.tcpdump -w dps_multicast.pcapng 'coap'
```

Filter unicast DPS packets:
```
$ tshark -r dps.tcpdump -w dps_unicast.pcapng 'udp[8:2]==85:01 and not icmp'
```

## docs_upload

Generates Doxygen API documentation and uploads it to the upstream
gh_pages branch.

`docs_upload`

## dps_graph.pl

Generates an input file to dot that graphs the TCP connections beween
instances of the reg_subs example program.

Run `test_scripts/reg1.py` or similar to create a network of connected
nodes.

`dps_graph.pl | dot -Tpng -o graph.png`

Generates a .png file for the connections.

## dtls_fuzzer

Runs the dtls_fuzzer for all server and client steps in parallel.

`dtls_fuzzer`

## exports

Scans the header files for symbols that need to be included in
dps_shared.def.

`exports > dps_shared.def`

## fuzzer_cov

Runs all existing corpus with coverage and generate report in
fuzzer_cov directory.

`fuzzer_cov`

Example:
```
$ rm *.profraw
$ scons ... transport=fuzzer cov=yes
$ ./fuzzer_cov
$ scons ... transport=dtls cov=yes
$ USE_DTLS=1 ./fuzzer_cov
```

## fuzzer_run

Runs all the fuzzers to generate more test cases.

`fuzzer_run`

Example:
```
$ scons ... transport=fuzzer
$ ./fuzzer_run
$ scons ... transport=dtls
$ USE_DTLS=1 ./fuzzer_run
```

## showmesh

Runs the make_mesh test on an input file and displays the resultant
graphs.

`tools/showmesh [-d] [-o <png file>] [-l <logfile>] [-k count] [-s <count>] [-e <engine>] <file>`

Requires graphviz and imagemagick (or some other png viewer)

    -d  -- debug
    -e  -- graphviz engine (default is fdp)
    -o  -- Capture the png output file
    -l  -- Capture the log file from make_mesh
    -s  -- Maximum number of subscriptions to register (default=1)
    -k  -- Maximum number of nodes to kill (default=0)

There are some sample meshes in the ./meshes subdir.

Active arcs are shown solid, muted arcs (if not hidden) are dotted.
