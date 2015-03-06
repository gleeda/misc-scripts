#!/usr/bin/perl -w
#
# Author: Gleeda 
#
# Grabs information from registry files in a memory image.  In addition to Volatility, 
# you must have VolRip installed:
#  http://moyix.blogspot.com/2009/03/regripper-and-volatility-prototype.html
# as well as VolReg:
#  http://www.cc.gatech.edu/~brendan/volatility/ 
# which requires Inline::Python:
#  http://search.cpan.org/~nine/Inline-Python/Python.pod
# and Inline::C
#  http://search.cpan.org/~sisyphus/Inline-0.46/C/C.pod
#
# USAGE:
#
# getregs.pl
#	(this must be run in your Volatility directory)
#
#	-f <image file>
#	-i <intput file from Volatility hivelist output>
#	-rsys  - RR system
#	-ruser - RR ntuser
#	-rsoft - RR software
#	-rsec  - RR security
#	-rsam  - RR samparse
#	-a     - Autoruns keys
#
#  
#  Redirect output into a text file
#
#  *nix only
#
#  Notes: currently has pauses in between each key that is queried for Autoruns (1s) and 
#         registry file that RR is run against (3s) to allow bailouts with SIGINT (CTRL+C)
# 
#         depending on what plugins you have installed and system setup, you may see complaints about yara
#         pydasm, pefile or whatever not being available or in your path.  just ignore these complaints
#

use Getopt::Long;

$usage  = "usage: $0\n(this must be run in your Volatility directory)\n\n\t-f <image file>\n\t-i <intput file from Volatility hivelist output>\n";
$usage .= "\t-rsys  - RR system\n\t-ruser - RR ntuser\n\t-rsoft - RR software\n\t-rsec  - RR security\n\t-rsam  - RR samparse\n\t-a     - Autoruns keys\n\n";

&GetOptions("f=s", \$IMAGE, "i=s", \$INPUT, "rsys", \$SYSTEM, "rsoft", \$SOFT, "ruser", \$NTUSER, "rsec", \$SEC, "rsam", \$SAM, "a", \$AUTO);

if (!defined $INPUT) {
  die $usage;
}

if (!defined $IMAGE) {
  die $usage;
}

#in case we wanna bail
$SIG{INT} = \&my_init_handler;

if (-e $INPUT) {
  open(FILE, $INPUT);
}else{
  die "Input file $INPUT not found!\n\n$usage";
}

unless (-e $IMAGE) {
  die "Image file $IMAGE not found!\n\n$usage";
}

if (!defined $SYSTEM && !defined $NTUSER && !defined $SOFT 
   && !defined $SOFT && !defined $SEC && !defined $SAM && !defined $AUTO) {
  print "You must pick a mode of query\n";
  die $usage;
}

#Get address and registry info from hivelist input file:
while (<FILE>) {
  chomp;
  @line = split("   ", $_);
  if ($line[0] ne "Address") {
    push (@mylocs, $line[1]);
    push (@myadds, $line[0]);
  }
}

if (defined $SYSTEM) {
  &RR("system");
}

if (defined $NTUSER) {
  &RR("ntuser");
}

if (defined $SOFT) {
  &RR("software");
}

if (defined $SEC) {
  &RR("security");
}

if (defined $SAM) {
  &RR("sam");
}

if (defined $AUTO) {
  &autoruns;
}

sub autoruns() {
  for $i (0..$#myadds) {
      print "*"x100 . "\n";
      print "*  FILE: $mylocs[$i] ($myadds[$i])\n";
      print "*  Value (if any):\n\n";
      system ("python ./volatility printkey -f $IMAGE -o $myadds[$i] -r false");
      print "*"x100 . "\n\n\n";
  }
  sleep 1;
}

sub RR() {
  my $plugins = shift;
  for $i (0..$#myadds) {
    print "*"x100 . "\n";
    print "*  FILE: $mylocs[$i] ($myadds[$i])\n*\n";
    system("perl ./rip.pl -r $IMAGE\@$myadds[$i] -f $plugins");
    print "*"x100 . "\n\n\n";
    sleep 3;
  }
}


sub my_init_handler{
  die "Exiting....\n\n";
}
