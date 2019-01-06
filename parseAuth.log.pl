#!/usr/bin/perl -w

use Regexp::Common;
use Net::DNS;
use Term::ANSIColor qw(:constants);
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

# Main Loop
foreach (@lines) {
	my $time;
	if ( $_ =~ /(^.*)$hostname/ ) { $time = $1; } # Timestamp is not yet used
	
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


print "We found ", $#IPs_accepted+1," different IPs from where we ACCEPTED connections\n";
printsummary(\%sshd_accepted_connections, "Accepted Connections", "5");

print "\nWe found ", $#IPs_failed+1," different Ips from where connections FAILED\n";
printsummary(\%sshd_failed_connections, "Failed Connections", "5");

print "\nWe found ",$#IPs_bad_protocol+1," different IPs who used BAD PROTOCOL\n";
printsummary(\%sshd_bad_protocol, "Bad Protocol", "5");



# Helper Functions
sub printsummary {
	my %tmphash = %{$_[0]};
	my $tmpinfotype = $_[1];
	my $tmpmaxtalkers = $_[2];
	my @tmpkeys = keys %tmphash;
	my @tmpvalues = values %tmphash;

	my @tmptoptalkers = sort { $b <=> $a } values %tmphash;

	print GREEN "---------------- ", RESET, "Showing TOP-5 Talkers ", GREEN, "----------------", RESET, "\n";
	for my $talker (@tmptoptalkers) {
		if ($tmpmaxtalkers > 0) {
			foreach (@tmpkeys) {
				if ($tmphash{$_} eq $talker) {
					print RED, $tmpinfotype, RESET, ": ", CYAN, $tmphash{$_}, RESET, " times from IP ", CYAN, $_, RESET, "\n";
					$tmpmaxtalkers--;
					if ( $tmpmaxtalkers <= 0) { last; }
				} 
			}
		} else {
			if ($debug > 3) { print "End the loop with tmpmaxtalkers = ", $tmpmaxtalkers, "\n"; }
			last;
		}
	}
	print GREEN, "-------------------------------------------------------", RESET, "\n";
}


ip_to_dnsname("192.168.213.3");

sub ip_to_dnsname {
	my $ip_to_check = $_[0];
	my $res = Net::DNS::Resolver->new;

	# change IP from 192.168.1.15 to 15.1.168.192.in-addr.arpa for searching
	my $target_IP = join('.', reverse split(/\./, $ip_to_check)).".in-addr.arpa";

	# query DNS
	my $query = $res->query("$target_IP", "PTR");

	# if a result is found
	if ($query){
		print("Resolves to:\n");
		# for every result, print the IP address
		foreach my $rr ($query->answer){
			# show all unless the type is PTR (pointer to a canonical name)
			next unless $rr->type eq "PTR";
		        # remove the period at the end
		        printf(substr($rr->rdatastr, 0, -1));
    		}
	} else {
	}
}


