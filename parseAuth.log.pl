#!/usr/bin/perl -w

use Regexp::Common; 
use strict;

my $authlogfile = "/tmp/auth.log";

my $debug = 0;


my $hostname = "SSH-Jumphost";




open my $handle, '<', $authlogfile;
chomp(my @lines = <$handle>);
close $handle;

my %sshd_accepted_connections;
my %sshd_failed_connections;
my %sshd_bad_protocol;

foreach (@lines) {
	my $time;
	if ( $_ =~ /(^.*)$hostname/ ) { $time = $1; }

	
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


my @IPs_accepted 	= keys %sshd_accepted_connections;
my @IPs_failed   	= keys %sshd_failed_connections;
my @IPs_bad_protocol	= keys %sshd_bad_protocol;
my @TopTalkers;

print "We found ", $#IPs_accepted+1," different IPs from where we ACCEPTED connections\n";
foreach (@IPs_accepted) {
	print "From $_ we have $sshd_accepted_connections{$_} acepted connections\n";
}


print "We found ", $#IPs_failed+1," different Ips from where connections FAILED\n";
foreach (@IPs_failed) {
	print "From $_ we have $sshd_failed_connections{$_} failed connections\n";
}

print "we found ",$#IPs_bad_protocol+1," different IPs who used BAD PROTOCOL\n";
@TopTalkers = sort { $b <=> $a } values %sshd_bad_protocol;
foreach (@IPs_bad_protocol) {

#	print "From $_ we have $sshd_bad_protocol{$_} bad protocol entries\n";
}

printsummary(\%sshd_accepted_connections, "Accepted Connections", "5");
printsummary(\%sshd_failed_connections, "Failed Connections", "5");
printsummary(\%sshd_bad_protocol, "Bad Protocol", "5");




# Helper Functions
sub printsummary {
	my %tmphash = %{$_[0]};
	my $tmpinfotype = $_[1];
	my $tmpmaxtalkers = $_[2];
	my @tmpkeys = keys %tmphash;
	my @tmpvalues = values %tmphash;

	my @tmptoptalkers = sort { $b <=> $a } values %tmphash;

	for my $talker (@tmptoptalkers) {
		if ($tmpmaxtalkers > 0) {
			foreach (@tmpkeys) {
				if ($tmphash{$_} eq $talker) {
					print $tmpinfotype, " occured ", $tmphash{$_}, " times from IP ", $_, "\n";
					$tmpmaxtalkers--;
				} 
			}
		} else {
			if ($debug > 3) { print "End the loop with tmpmaxtalkers = ", $tmpmaxtalkers, "\n"; }
			last;
		}
	}
}
