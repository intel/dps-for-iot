#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper qw(Dumper);

my (@nodes, %arcs) = ((), ());

foreach my $filename (@ARGV) {
    my ($a);
    open(my $fh, '<', $filename) or die "Could not open file '$filename' $!";
    while (my $line = <$fh>) {
    chomp($line);
        if ($line =~ /node .*:(\d+)$/) {
            $a = $1;
            push(@nodes, $a)
        } elsif ($line =~ /.* [DEBUG|TRACE|ERROR]/) {
            # Ignore debug output
        } elsif ($line =~ /  .*:(\d+) muted=(\d)/) {
            my ($b, $muted) = ($1, $2);
            if ($a > $b) {
                $arcs{"$a -- $b"} = $muted;
            }
        }
    }
    close($fh);
}

my ($nnodes, $narcs, $nmuted) = (scalar(@nodes), scalar(%arcs), 0);
foreach my $arc (keys(%arcs)) {
    if ($arcs{$arc} eq "1") {
        ++$nmuted;
    }
}

print "graph {\n";
print "  node[shape=circle, fontsize=10, margin=\"0.01,0.01\", fixedsize=true];\n";
print "  overlap=false;\n";
print "  splines=true;\n";
print "  subgraph cluster_1 {\n";
print "    style=invis;\n";
print "    1000[shape=none, width=1, style=bold, height=1, fontsize=12, label=\"nodes=$nnodes\\narcs=$narcs\\nmuted=$nmuted\"];\n";
print "    subgraph cluster1 {\n";
print "      node[style=filled, fillcolor=palegreen3];\n";
foreach my $arc (keys(%arcs)) {
    if ($arcs{$arc} eq "0") {
        print "      $arc [len=1];\n";
    } elsif ($arcs{$arc} eq "1") {
         #print "      $arc [len=1,color=red,style=dotted];\n";
    }
}
print "    }\n";
print "  }\n";
print "}\n";
