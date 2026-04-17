#!/usr/bin/env perl

use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;

use Net::Whois::IANA;

# =============================================================================
# Verify that *_read_query functions warn when print to socket fails.
# =============================================================================

# --- FailPrintHandle: tied filehandle where PRINT always fails ---
{
    package FailPrintHandle;
    use Tie::Handle;
    use base 'Tie::Handle';

    sub TIEHANDLE {
        my ( $class, $lines ) = @_;
        return bless { lines => [ @{ $lines || [] } ], closed => 0 }, $class;
    }
    sub PRINT    { $! = 5; return 0 }    # simulate write failure (EIO)
    sub READLINE {
        my ($self) = @_;
        return undef if $self->{closed};
        return shift @{ $self->{lines} };
    }
    sub CLOSE { $_[0]->{closed} = 1; return 1 }
}

my $sock_counter = 0;

sub fail_sock {
    my ($lines) = @_;
    my $name = "FailPrintHandle::SOCK_" . ++$sock_counter;
    no strict 'refs';
    tie *{$name}, 'FailPrintHandle', $lines;
    return \*{$name};
}

# Helper: minimal response lines so the function completes
my @ripe_lines = (
    "inetnum:        10.0.0.0 - 10.0.0.255\n",
    "country:        XX\n",
);

subtest 'ripe_read_query warns on print failure' => sub {
    my $sock = fail_sock(\@ripe_lines);
    my $warnings = warnings { Net::Whois::IANA::ripe_read_query($sock, '10.0.0.1') };
    ok scalar @$warnings, 'produces warning(s)';
    like $warnings->[0], qr/write failed/, 'warning mentions write failure';
};

subtest 'apnic_read_query warns on print failure' => sub {
    my $sock = fail_sock(\@ripe_lines);
    my $warnings = warnings { Net::Whois::IANA::apnic_read_query($sock, '10.0.0.1') };
    ok scalar @$warnings, 'produces warning(s)';
    like $warnings->[0], qr/write failed/, 'warning mentions write failure';
};

subtest 'arin_read_query warns on print failure' => sub {
    my @arin_lines = (
        "OrgName:        Example Org\n",
        "NetRange:       10.0.0.0 - 10.0.0.255\n",
    );
    my $sock = fail_sock(\@arin_lines);
    my $warnings = warnings { Net::Whois::IANA::arin_read_query($sock, '10.0.0.1') };
    ok scalar @$warnings, 'produces warning(s)';
    like $warnings->[0], qr/write failed/, 'warning mentions write failure';
};

subtest 'lacnic_read_query warns on print failure' => sub {
    my @lacnic_lines = (
        "inetnum:     10.0.0.0/24\n",
        "owner:       Example\n",
        "country:     BR\n",
    );
    my $sock = fail_sock(\@lacnic_lines);
    my $warnings = warnings { Net::Whois::IANA::lacnic_read_query($sock, '10.0.0.1') };
    ok scalar @$warnings, 'produces warning(s)';
    like $warnings->[0], qr/write failed/, 'warning mentions write failure';
};

subtest 'jpnic_read_query warns on print failure' => sub {
    my @jpnic_lines = (
        "a. [Network Number]  10.0.0.0/24\n",
        "country:        JP\n",
    );
    my $sock = fail_sock(\@jpnic_lines);
    my $warnings = warnings { Net::Whois::IANA::jpnic_read_query($sock, '10.0.0.1') };
    ok scalar @$warnings, 'produces warning(s)';
    like $warnings->[0], qr/write failed/, 'warning mentions write failure';
};

done_testing;
