#!/usr/bin/perl -w

my $authlogfile = "/tmp/auth.log";

@lines = <$authlogfile>;

print @lines;
