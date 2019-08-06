#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper qw(Dumper);
use Graph::Undirected;
use List::Util qw(min max);
use Statistics::Basic qw(:all);

my $graph = Graph::Undirected->new;
my $muted = Graph::Undirected->new;
my %subgraphs;
my @path_lengths = ();

my (@roles, @topics, @nodes) = ((), (), ());

foreach my $filename (@ARGV) {
    my ($a, $role, $topic);
    open(my $fh, '<', $filename) or die "Could not open file '$filename' $!";
    while (my $line = <$fh>) {
	chomp($line);
	if ($line =~ /discover\d+ -(p|s) (\d+)$/) {
	    ($role, $topic) = ($1, $2);
	    push(@roles, $role);
	    push(@topics, $topic);
	} elsif ($line =~ /node .*:(\d+)$/) {
	    $a = $1;
	    push(@nodes, $a);
	    if (exists($subgraphs{$topic}{$role})) {
		push(@{$subgraphs{$topic}{$role}}, $a);
	    } else {
		$subgraphs{$topic}{$role} = [$a];
	    }
	} elsif ($line =~ /  .*:(\d+) (UNLINKED|LINKED) muted=(\d\/\d)/) {
	    my ($b, $m) = ($1, $3);
	    if ($m eq "0/0") {
		if (!$graph->has_edge($a, $b) && !$graph->has_edge($b, $a)) {
		    $graph->add_edge($a, $b);
		}
	    } else {
		if (!$muted->has_edge($a, $b) && !$muted->has_edge($b, $a)) {
		    $muted->add_edge($a, $b);
		}
	    }
	}
    }
    close($fh);
}

foreach my $topic (keys %subgraphs) {
    foreach my $p (@{$subgraphs{$topic}{"p"}}) {
	foreach my $s (@{$subgraphs{$topic}{"s"}}) {
	    my @path = $graph->SP_Dijkstra($p, $s);
	    push(@path_lengths, scalar(@path));
	}
    }
}

my $label =
    "\"Nodes=" . $graph->vertices() .
    "\\lArcs=" . $graph->edges() .
    "\\lMuted=" . $muted->vertices() .
    "\\lMean=" . mean(@path_lengths) .
    "\\lStd Dev=" . stddev(@path_lengths) .
    "\\lMinimum=" . min(@path_lengths) . " [" . scalar(grep { $_ == min(@path_lengths) } @path_lengths) . "]" .
    "\\lMaximum=" . max(@path_lengths) . " [" . scalar(grep { $_ == max(@path_lengths) } @path_lengths) . "]" .
    "\\lMedian=" . median(@path_lengths) . " [" . scalar(grep { $_ == median(@path_lengths) } @path_lengths) . "]" .
    "\\l\"";

print "graph {\n";
print "  node[fontsize=10, margin=\"0.01,0.01\", fixedsize=true, colorscheme=\"paired12\"];\n";
print "  overlap=false;\n";
print "  splines=true;\n";
print "  subgraph cluster_1 {\n";
print "    style=invis;\n";
print "    1000[shape=none, width=1, style=bold, height=1, fontsize=12, label=$label];\n";
print "    subgraph cluster1 {\n";
for (my $i = 0; $i < scalar(@nodes); ++$i) {
    my $shape = $roles[$i] eq "p" ? "doublecircle" : "circle";
    print "      $nodes[$i]\[shape=$shape, style=filled, color=\"$topics[$i]\"];\n";
}
foreach my $e ($graph->edges()) {
    my ($a, $b) = @{$e};
    print "      $a -- $b [len=1, dir=both];\n";
}
# TODO including muted links tends to overload graphviz
#foreach my $e ($muted->edges()) {
#    my ($a, $b) = @{$e};
#    print "      $a -- $b [len=1, dir=both, style=dotted];\n";
#}
print "    }\n";
print "  }\n";
print "}\n";
