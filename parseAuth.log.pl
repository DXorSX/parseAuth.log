#!/usr/bin/perl -w

use Regexp::Common;
use Net::DNS;
use Net::Whois::IP;
use Term::ANSIColor qw(:constants);
use Time::ParseDate;
use strict;

my $authlogfile = "/tmp/auth.log"; 	# Where to find the logfile.
my $hostname = "SSH-Jumphost";			# We need to know the name oft the Host where the lgofile was generated. It's needed to find specific lines.
my $debug = 0;											# Just for debuging, if $debug >0 you will see a lot of output.

# Open the logfile an get all Data into a Array
open my $handle, '<', $authlogfile;
chomp(my @lines = <$handle>);
close $handle;

# Create some Hashes to store the findings.
my %sshd_accepted_connections;
my %sshd_failed_connections;
my %sshd_bad_protocol;

my $DateTimeOldestRecord = parsedate("today");
my $DateTimeYoungestRecord = 0;

# Main Loop
foreach (@lines) {
	my $seconds_since_jan1_1970;
	if ( $_ =~ /(^.*)$hostname/ ) { 
		$seconds_since_jan1_1970 = parsedate($1,PREFER_PAST => 1); 
		if ($seconds_since_jan1_1970 < $DateTimeOldestRecord) { 
			$DateTimeOldestRecord = $seconds_since_jan1_1970; 

		}
		if ($seconds_since_jan1_1970 > $DateTimeYoungestRecord) {
			$DateTimeYoungestRecord = $seconds_since_jan1_1970;
		}

	}

	if ( $_ =~ /.*sshd.*Accepted publickey/ )		
	{
		if ( $_ =~ /($RE{net}{IPv4})/ )
		{
			if ( exists ($sshd_accepted_connections{$1}) ) {
				$sshd_accepted_connections{$1}++;
			} else {
				$sshd_accepted_connections{$1} = 1;
			}
			if ($debug > 1) { print "Debug Accepted: ", $_, "\n"; }
			if ($debug > 1) { print "Debug Accepted: ", $1, "\n"; }
			if ($debug > 0) { print "Debug Accepted: ", $1, " => ", $sshd_accepted_connections{$1}, "\n" ;}
		}
	}
	elsif (( $_ =~ /.*sshd.*error/ ) || ( $_ =~ /.*sshd.*Failed/ ))
	{
		if ( $_ =~ /($RE{net}{IPv4})/ )
		{
			if ( exists ($sshd_failed_connections{$1}) ) {
				$sshd_failed_connections{$1}++;
			} else {
				$sshd_failed_connections{$1} = 1;
			}
			if ($debug > 1) { print "Debug Failed: ", $_, "\n"; }
			if ($debug > 1) { print "Debug Failed: ", $1, "\n"; }
			if ($debug > 0) { print "Debug Failed: ", $1, " => ", $sshd_failed_connections{$1}, "\n" ;}
		}
	}
	elsif ( $_ =~ /.*sshd.*Bad protocol/ ) 
	{
		if ( $_ =~ /($RE{net}{IPv4})/ )
		{
			if ( exists ($sshd_bad_protocol{$1}) ) {
				$sshd_bad_protocol{$1}++;
			} else {
				$sshd_bad_protocol{$1} = 1;
			}
			if ($debug > 1) { print "Debug Bad proto: ", $_, "\n"; }
			if ($debug > 1) { print "Debug Bad proto: ", $1, "\n"; }
			if ($debug > 0) { print "Debug Bad proto: ", $1, " => ", $sshd_bad_protocol{$1}, "\n" ;}
		}
	}
}


print "Oldest Date   : ", UNDERLINE MAGENTA,scalar localtime( $DateTimeOldestRecord),RESET ,"\n";
print "Youngest Date : ", UNDERLINE MAGENTA, scalar localtime( $DateTimeYoungestRecord ),RESET, "\n";

my @IPs_accepted 	= keys %sshd_accepted_connections;
my @IPs_failed   	= keys %sshd_failed_connections;
my @IPs_bad_protocol	= keys %sshd_bad_protocol;

print "We found ", YELLOW, $#IPs_accepted+1, RESET, " different IPs from where we ACCEPTED connections\n";
printsummary(\%sshd_accepted_connections, "Accepted Connections", "5");

print "\nWe found ", YELLOW, $#IPs_failed+1, RESET, " different IPs from where connections FAILED\n";
printsummary(\%sshd_failed_connections, "Failed Connections", "5");

print "\nWe found ",YELLOW, $#IPs_bad_protocol+1, RESET, " different IPs who used BAD PROTOCOL\n";
printsummary(\%sshd_bad_protocol, "Bad Protocol", "10");



# Helper Functions
sub printsummary {
	my %tmphash = %{$_[0]};
	my $tmpinfotype = $_[1];
	my $tmpmaxtalkers = $_[2];
	my @tmpkeys = keys %tmphash;
	my @tmpvalues = values %tmphash;

	my @tmptoptalkers = sort { $b <=> $a } values %tmphash;

	print GREEN "----------------------------- ", RESET, "Showing TOP-",$tmpmaxtalkers, " Talkers ", GREEN, "-----------------------------------------", RESET, "\n";
	for my $talker (@tmptoptalkers) {
		if ($tmpmaxtalkers > 0) {
			foreach (@tmpkeys) {
				if ($tmphash{$_} eq $talker) {
					my $response = whoisip_query($_);
					if ( not length $response->{country} ) { $response->{country} = "n/a" }
					if ( not length $response->{descr} ) { $response->{descr} = "n/a" }
				
					print RED, $tmpinfotype, RESET, ": ", CYAN, $tmphash{$_}, RESET, " times from IP ", CYAN, $_, RESET, "\t ( Country: ", $response->{country} ,", ", $response->{descr}  ," )\n";
					$tmpmaxtalkers--;
					if ( $tmpmaxtalkers <= 0) { last; }
				} 
			}
		} else {
			if ($debug > 3) { print "End the loop with tmpmaxtalkers = ", $tmpmaxtalkers, "\n"; }
			last;
		}
	}
	print GREEN, "---------------------------------------------------------------------------------------------", RESET, "\n";
}




