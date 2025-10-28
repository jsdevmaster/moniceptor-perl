#!/usr/bin/perl
use strict;
use warnings;
use DBI;

my $dsn      = "DBI:mysql:database=s1;host=silentbutdeadly.tplinkdns.com;port=3306";
my $db_user  = "bueno";
my $db_pass  = "warPita";

our $dbh = DBI->connect(
    $dsn, $db_user, $db_pass,
    { RaiseError => 1, AutoCommit => 1 }
) or die "Cannot connect to database: $DBI::errstr";

1;
