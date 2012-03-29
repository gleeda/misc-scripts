#!/usr/bin/perl
# Author: Jamie Levy (Gleeda)
# 
# virustotal.pl
#
# Takes in a tab separated hashfile (md5sum or sha1sum) or 
#   traditional 2 space delimited hash file 
#   prints out an html report from virustotal
#
# Updated 2010/12/7 to updated virustotal forms
#


# Create a user agent object
use LWP::UserAgent;
use Getopt::Long;
use Cwd;
use utf8;

$usage = "usage: $0 \n\t-d <output directory (opt)> \n\t-f <hash file> \n\t-t (optional, tab delimited hashfile)\n";
&GetOptions("d=s", \$DIR, "f=s", \$FILE, "p=s", "t", \$TAB);

$SIG{INT} = \&my_init_handler;

die $usage unless defined $FILE;

if( ! -e $FILE) {
  die "can't find file: $FILE\n$usage";
}

if( defined $DIR ){
  if( ! -d $DIR ){
    mkdir $DIR or die;
    print "made directory: $DIR for output\n";
  }
}else{
  $DIR = cwd;
}

%HASHES = ();
&gethashes;
&Chdir($DIR);

open INDEX,  ">:utf8", "index.html";
print INDEX "<HTML><HEAD><TITLE>Virus Total Results for Case</TITLE>";
print INDEX "<meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\" /></HEAD><BODY>\n";
print INDEX "<table border=1 align=\"center\" width=90%>\n";
print INDEX "<TBODY >\n<tr>";
print INDEX "<th vAlign=top align=center width=\"50%\">\n";
print INDEX "<b>File Name(s)</b></th>\n";
print INDEX "<th vAlign=top align=center width=\"30%\">\n";
print INDEX "<b>Hash Value</b></th>\n";
print INDEX "<th vAlign=top align=center width=\"20%\">\n";
print INDEX "<b>Percentage</b></th></tr>\n";


foreach $key (%HASHES) {
  if ($key =~ /[0-9a-fA-F]{32}/) {
    my @temp = split /::/, $HASHES{$key};
    print "processing hash: $key for file $HASHES{$key}\n";
    print INDEX "<tr><td vAlign=top align=left width=\"50%\">\n";
    foreach $h (@temp) {
      print INDEX "$h<br><br>\n";
    }
    print INDEX "</td>";
    print INDEX "<td vAlign=top align=left width=\"30%\">\n";
    &posthash($key);
    sleep (5);
  }
}

print INDEX "</TBODY></TABLE></HTML>\n";

close (INDEX);

print "open index.html in the $DIR directory\n";

sub Chdir{
  my $dir = shift;
        
  chdir $dir or
  die "unable to change to directory $dir\n";
}

sub my_init_handler{
  print INDEX "</TBODY></TABLE></HTML>\n";
  close (INDEX);
  die "index was written...\n";
}

sub gethashes {
  open (INPUT, $FILE);
  binmode INPUT, ":utf8";
  while (<INPUT>) {
    chomp;
    s/^\s+//;
    s/\s+$//;
    my @temp;
    if (defined $TAB) {
        @temp = split /\t/;
        if (defined $HASHES{$temp[1]}) {
          $HASHES{$temp[1]} .= "::$temp[0]";
        }else{
          $HASHES{$temp[1]} = $temp[0];
        }
    }else{
        @temp = split /  /;
        if (defined $HASHES{$temp[0]}) {
          $HASHES{$temp[0]} .= "::$temp[1]";
        }else{
          $HASHES{$temp[0]} = $temp[1];
        }
    }
    
    
  }
  close (INPUT);
}

sub posthash {  
  $HASH = @_[0];
  open(OUT, ">$HASH.html");
  print "processing $HASH\n";
  $ua = LWP::UserAgent->new;
  $ua->agent("Mozilla/4.0");
  $base = "http://www.virustotal.com";

  # Create a request
  my $loc = $base . "/search.html";
  print "posting to $loc\n";
  my $req = HTTP::Request->new(POST => $loc);
  $req->content_type('application/x-www-form-urlencoded');
  $req->content('chain=' . $HASH);
  print "HASH: $HASH\n";

  # Pass request to the user agent and get a response back
  my $res = $ua->request($req);

  # Check the outcome of the response
  if ($res->is_redirect ) {
        $url = $res->header("Location");

    print "getting from $url\n";
    if ($url !~ /(report|id|analysis)/) {
      print INDEX "$HASH (not found)</td><td align=center><font color=\"blue\">N/A</font></td></tr>\n";
      close(OUT);
      unlink "$HASH.html";
    }
    else {
      print INDEX "<a href=\"$HASH.html\">$HASH</a></td>\n";
      print INDEX "<td vAlign=top align=center width=\"20%\">\n";
      $req = HTTP::Request->new(GET => $url);
      $req->content_type('application/x-www-form-urlencoded');
      $res = $ua->request($req);

      if ($res->is_success) {
        print OUT $res->content;
        $content = $res->content;
        if ($content =~ m/<td class=\" text-red \">(.*?)<\/td>/ism) {
            $num = split /\/ [0-9][0-9]/, $1;
            if ($num > 0){
               print INDEX "<b><font color=\"red\">" . $num."<\/font><\/b>\/";
            }else{
               print INDEX "<b>" . $num."<\/b>\/";
            }
            @total_av = split /\//, $1; 
            print INDEX $total_av[1]."</td></tr>\n";
        } elsif ($content =~ m/<td class=\" text-green \">(.*?)<\/td>/ism) {
            @total_av = split /\//, $1; 
            print INDEX "<font color=\"blue\">0</font> / " . $total_av[1] . "</td></tr>\n";
         }   
      }
      else {
        print $res->status_line, "\n";
      }
    }
  }
  else {
    print OUT "failed to retrieve hash\n";
  }
  close (OUT);
}
