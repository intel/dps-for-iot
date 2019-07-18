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
	} elsif ($line =~ /  .*:(\d+) (UNLINKED|LINKED) muted=(\d)\/(\d)/) {
	    my ($b, $outbound_muted, $inbound_muted) = ($1, $3, $4);
	    my $ab_muted = "$outbound_muted/$inbound_muted";
	    my $ba_muted = "$inbound_muted/$outbound_muted";
	    if (($arcs{"$a -- $b"} && $arcs{"$a -- $b"} eq $ab_muted) ||
		($arcs{"$b -- $a"} && $arcs{"$b -- $a"} eq $ba_muted)) {
		# arc is entered or symmetrical with respect to
		# muting, so only include one arc in the graph
	    } else {
		$arcs{"$a -- $b"} = $ab_muted;
	    }
	}
    }
    close($fh);
}

my ($nnodes, $narcs, $nmuted) = (scalar(@nodes), scalar(%arcs), 0);
foreach my $arc (keys(%arcs)) {
    # when either direction is muted, PUBs will not be sent
    if ($arcs{$arc} ne "0/0") {
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
    if ($arcs{$arc} eq "0/0") {
	print "      $arc [len=1,dir=both];\n";
    } elsif ($arcs{$arc} eq "0/1") {
	print "      $arc [len=1,dir=forward,style=dotted];\n";
    } elsif ($arcs{$arc} eq "1/0") {
	print "      $arc [len=1,dir=back,style=dotted];\n";
    } elsif ($arcs{$arc} eq "1/1") {
	# TODO including muted links tends to overload graphviz
#   print "      $arc [len=1,dir=none,color=red,style=dotted];\n";
    }
}
print "    }\n";
print "  }\n";
print "}\n";
