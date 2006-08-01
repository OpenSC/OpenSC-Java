#! /usr/bin/perl -w
#
# $Id: config.pl 242 2006-07-08 14:59:13Z lech $
#
# Author: Wolfgang Glas/EV-i
#
# My own, small replacement for configure.
#

use File::Find;
use File::Path;
use File::Basename;
use File::Compare;
use Sys::Hostname;
use Config;
use Cwd;

sub wanted;

$top_confdir=File::Basename::dirname($0);

($top_srcdir=$top_confdir)=~ s%/scripts/?$%%;

$cwd=Cwd::getcwd();

print "Configuring directory '$cwd' for source tree '$top_srcdir'.\n";

%ac_vars=();
%defines=();
@conditions=();
%infiles=();
%headers=();

$debug=0;

$iarg=0;

if (defined $ARGV[0] && $ARGV[0] eq "-d") {
    $debug=1;
    ++$iarg;
}

$ac_vars{"MAKE"}="make";
$ac_vars{"ARCHNAME"}=$Config{'archname'};
$ac_vars{"HOSTNAME"}=hostname();

parsefile("$top_confdir/config.data.default");
parsefile("./config.data");

while ($iarg <= $#ARGV) {
    
    if ($ARGV[$iarg] =~ /^-D/) {

        $defstr = $ARGV[$iarg];
        $defstr =~ s/^-D//;

        ($var,$val) = split /=/,$defstr,2;

        ($arg = $var) =~ s/^[A-Za-z][A-Za-z0-9_]*((?:\(.+\))?)$/$1/;
        $var =~ s/^([A-Za-z][A-Za-z0-9_]*)\(.+\)$/$1/;

        $defines{$var} = [$arg,$val];
    } else {
        ($var,$val) = split /=/,$ARGV[$iarg],2;
        $ac_vars{$var}=$val;
    }

    ++$iarg;
}

for $i (0 .. $#conditions) {
    $k=$conditions[$i][0];
    $cond=$conditions[$i][1];

    if (eval $k) {
        ($item,$spec) = split / +/,$cond,2;
        

        if ($item eq 'ac') {
            ($var,$val) = split / *= */,$spec,2;
            $ac_vars{$var} = $val;   
        }
        else {
            if ($item eq 'define') {
                ($var,$val) = split / *= */,$spec,2;
                ($arg = $var) =~ s/^[A-Za-z][A-Za-z0-9_]*((?:\(.+\))?)$/$1/;
                $var =~ s/^([A-Za-z][A-Za-z0-9_]*)\(.+\)$/$1/;

                $defines{$var} = [$arg,$val];               
            }
            else {
                if ($item eq 'undef') {
                    delete $defines{$spec};  
                }
                else {
                    die "Error in condition $k: Invalid item type $item found in condition.\n";
                }
            }
        }
    }
}

if ($debug)
{
    foreach $k (sort keys %ac_vars) {
        print "ac $k $ac_vars{$k}\n";
    }

    foreach $k (sort keys %defines) {
        $arg=$defines{$k}[0];
        $val=$defines{$k}[1];
        print "define $k $arg $val\n";
    }
}

# Traverse desired filesystems
File::Find::find({wanted => \&wanted}, $top_srcdir);

foreach $fn (sort keys %infiles) 
{
    process_other($fn,$infiles{$fn});
}

foreach $fn (sort keys %headers) 
{
    process_header($fn,$headers{$fn});
}

print "Creating file reconfigure.sh.\n";

open OUT,">reconfigure.sh" or die "Error opening reconfigure.sh: $!";

print OUT "#!/bin/sh\n";
print OUT "# automatically created by $0\n";
print OUT 'cd `dirname $0`';
print OUT "\nperl -w $top_srcdir/scripts/config.pl";

for $i (0 .. $#ARGV) {
    $qarg = $ARGV[$i];
    $qarg =~ s/\'/\'\"\'\"\'/g;

    print OUT " '$qarg'";
}

print OUT "\n";

close OUT;
chmod 0775, "reconfigure.sh";

exit;

sub parsefile {
    my $fn = shift;
    my $item;
    my $spec;
    my $var;
    my $arg;
    my $val;
    my $cond;
    my $phrase;

    open IN,$fn or die "Error opening $fn: $!";

    while(<IN>) {
        chomp;
        
        if (!($_ =~ /^\#/) && !($_ =~ /^\s*$/)) {

            ($item,$spec) = split / +/,$_,2;
        

            if ($item eq 'ac') {
                ($var,$val) = split / *= */,$spec,2;
                $ac_vars{$var} = $val;   
            }
            else {
                if ($item eq 'define') {
                    ($var,$val) = split / *= */,$spec,2;
                    ($arg = $var) =~ s/^[A-Za-z][A-Za-z0-9_]*((?:\(.+\))?)$/$1/;
                    $var =~ s/^([A-Za-z][A-Za-z0-9_]*)\(.+\)$/$1/;

                    $defines{$var} = [$arg,$val];               
                }
                else {
                    if ($item eq 'test') {
                        ($cond,$phrase) = split / *then */,$spec,2;
                        $cond =~ /^\s*\{.*\}\s*$/ or die "Error reading $fn: Invalid test condition $cond found.";
                        $cond =~ s/^\s*\{(.*)\}\s*$/$1/;
                        $cond =~ s/\$([A-Za-z][A-Za-z0-9_]*)/\$ac_vars{$1}/g;
                        
                        $phrase =~ /^\s*\{.*\}\s*$/ or die "Error reading $fn: Invalid test phrase $phrase found.";
                        $phrase =~ s/^\s*\{(.*)\}\s*$/$1/;

                        push @conditions, [$cond,$phrase];
                    }
                    else {
                        if ($item eq 'undef') {
                            delete $defines{$spec};  
                        }
                        else {
                            die "Error reading $fn: Invalid item type $item found.\n";
                        }
                    }
                }
            }
        }
    }
    close IN;
}

sub open_outfile {
    my $fn = shift;
    my $dir = File::Basename::dirname($fn);

    if (! -d $dir) {
        File::Path::mkpath($dir);
    }

    open OUT,">$fn" or die "Error opening $fn: $!";
}

sub process_header {
    my $fn = shift;
    my $dir = shift;
    my $var;
    my $line;
    my $outfn;

    $outfn=$fn;

    $outfn =~ s%^$top_srcdir/%./%;
    $outfn =~ s%\.in$%%;
   
    open IN,$fn or die "Error opening $fn: $!";
    open_outfile("$outfn~");

    print OUT "/* config.h.  Generated by configure.  */\n";

    while(<IN>) {
        chomp;
        $line = $_;
        if ($line =~ /^\#undef[ \t]([_A-Z][A-Z0-9_]*)/ ) {

            $var = $line;
            $var =~ s%^\#undef[ \t]([_A-Z][A-Z0-9_]*).*%$1%;


            if (defined $defines{$var}) {
                $arg=$defines{$var}[0];
                $val=$defines{$var}[1];

                if (defined $arg) {
                    $line = "#define $var$arg $val";
                } else {
                    $line = "#define $var $val";
                }
            } else {
                $line = "/* $line */";
            }
        }
        print OUT "$line\n";
    }
    close OUT;
    close IN;

    if (-f $outfn && File::Compare::compare($outfn,"$outfn~") == 0) {
        print "File $outfn is unchanged.\n";
    } else {
        print "Creating file $outfn.\n";
        rename "$outfn~",$outfn;
    }
}

sub process_other {
    my $fn = shift;
    my $dir = shift;
    my $reltopdir;
    my $outfn;

    $outfn=$fn;
    $reltopdir=$dir;
    if ($reltopdir eq $top_srcdir) {
        $reltopdir = "";
    }
    else {
        $reltopdir =~ s%^$top_srcdir/%%;
        $reltopdir =~ s%[^/]+/%../%g;
        $reltopdir =~ s%[^/]+$%..%;
        $reltopdir = "$reltopdir/";
    }

    $outfn =~ s%^$top_srcdir/%./%;
    $outfn =~ s%\.in$%%;

    $ac_vars{"top_srcdir"}="$reltopdir$top_srcdir";
    $ac_vars{"srcdir"}="$reltopdir$dir";

    open IN,$fn or die "Error opening $fn: $!";
    open_outfile($outfn);

    print "Creating file $outfn.\n";

    while(<IN>) {
        $line = $_;
        $line =~ s%@([a-zA-Z][a-zA-Z0-9_]*)@%$ac_vars{$1}%ge;
  
        print OUT $line;
    }
    close OUT;
    close IN;
}


sub wanted {
    my $reltopdir;
    my $subd;

    if (/^config\.h\.in\z/s) {
        $headers{$File::Find::name}=$File::Find::dir;
    } else {
        if (/^Makefile\.in\z/ && ! ($File::Find::dir eq $top_srcdir)) {
            $reltopdir=$File::Find::dir;
            $reltopdir =~ s%^$top_srcdir/%%;
            $subd=$ac_vars{"SUBDIRS"};
            if (defined $subd) {
                $ac_vars{"SUBDIRS"} = "$subd $reltopdir";
            } else {
                $ac_vars{"SUBDIRS"} = $reltopdir;
            }
        }
        if (/^.*\.in\z/s) {
            $infiles{$File::Find::name}=$File::Find::dir;
        }
    }
}
