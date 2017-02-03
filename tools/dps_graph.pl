#!/usr/bin/perl

open(SS, "ss -p -a |");

while ( <SS> )
{
    if (/ESTAB.*reg_subs/ || /ESTAB.*subscriber/) {
        my @elem = split(/ +/);
        my ($addr, $localPort) = @elem[4] =~ /([0-9,a-f,A-F,:]+):([0-9]+)$/;
        my ($addr, $peerPort) = @elem[5] =~ /([0-9,a-f,A-F,:]+):([0-9]+)$/;
        my ($pre, $pid, $post) =  @elem[6] =~ /(.*pid=)([0-9]+)(.*)/;
        push(@{$links{$pid}}, $peerPort);
    }
    if (/LISTEN.*reg_subs/ || /LISTEN.*subscriber/) {
        my @elem = split(/ +/);
        my ($addr, $listenPort) = @elem[4] =~ /([0-9,a-f,A-F,:]+):([0-9]+)$/;
        my ($pre, $pid, $post) =  @elem[6] =~ /(.*pid=)([0-9]+)(.*)/;
        $nodes{$listenPort} = $pid;
        push(@{$listener{$pid}}, $listenPort);
    }
}

print "digraph G {\n";
foreach $pid (keys %links)
{
    foreach $port (@{$links{$pid}}) {
        if (exists($nodes{$port})) {
            $label = "@{$listener{$pid}}";
            if ($label == "") {
                $label = "N/A";
            }
            print "    $pid [label=\"$label\"];\n";
            print "    $pid -> $nodes{$port}";
        }
    }
    print "\n";
}
print "}\n";
