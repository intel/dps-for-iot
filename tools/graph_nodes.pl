#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper qw(Dumper);

my (@nodes, %live, %mute) = ((), (), ());

foreach my $filename (@ARGV) {
    my ($n);
    open(my $fh, '<', $filename) or die "Could not open file '$filename' $!";
    while (my $line = <$fh>) {
    chomp($line);
        if ($line =~ /node .*:(\d+)$/) {
            $n = $1;
            push(@nodes, $n)
        } elsif ($line =~ /.* [DEBUG|TRACE|ERROR|INFO]/) {
            # Ignore debug output
        } elsif ($line =~ /  .*:(\d+) muted=(\d)/) {
            my ($a, $b, $muted) = ($n, $1, $2);
            # Keep all arcs going the same way
            if (exists($live{"$b -- $a"}) or exists($mute{"$b -- $a"})) {
                ($a, $b) = ($b, $a);
            }
            if ($muted eq "0") {
                if (exists($live{"$a -- $b"})) {
                    $live{"$a -- $b"} += 1;
                } else {
                    $live{"$a -- $b"} = 1;
                }
            } else {
                if (exists($mute{"$a -- $b"})) {
                    $mute{"$a -- $b"} += 1;
                } else {
                    $mute{"$a -- $b"} = 1;
                }
            }
        }
    }
    close($fh);
}

my ($nnodes, $narcs, $nmuted, $show_muted) = (scalar(@nodes), scalar(%live), scalar(%mute), 0);
$narcs += $nmuted;

print "graph {\n";
print "  node[shape=circle, fontsize=10, margin=\"0.01,0.01\", fixedsize=true];\n";
print "  overlap=false;\n";
print "  splines=true;\n";
print "  subgraph cluster_1 {\n";
print "    style=invis;\n";
print "    1000[shape=none, width=1, style=bold, height=1, fontsize=12, label=\"nodes=$nnodes\\narcs=$narcs\\nmuted=$nmuted\"];\n";
print "    subgraph cluster1 {\n";
print "      node[style=filled, fillcolor=palegreen3];\n";
foreach my $arc (keys(%live)) {
    if ($live{$arc} == 2) {
        print "      $arc [len=1];\n";
    } else {
        print "      $arc [len=1, style=dotted];\n";
    }
}
if ($show_muted) {
    foreach my $arc (keys(%mute)) {
        if (not exists($live{$arc})) {
            print "      $arc [len=1, color=red, style=dotted];\n";
        }
    }
}
print "    }\n";
print "  }\n";
print "}\n";
