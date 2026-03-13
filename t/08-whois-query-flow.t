#!/usr/bin/env perl

use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;

use Net::Whois::IANA;

use Test::MockModule;

# =============================================================================
# Unit tests for whois_query(), source_connect(), and is_mine().
# Fully mocked — no network required.
# =============================================================================

my $mock_iana = Test::MockModule->new('Net::Whois::IANA');

# --- helper: build a mock socket that yields lines from an arrayref ---

{
    package FakeSocket;
    sub new {
        my ( $class, $lines ) = @_;
        return bless { lines => [ @{ $lines || [] } ], closed => 0 }, $class;
    }
    sub print { 1 }    # absorb query writes
    sub close { $_[0]->{closed} = 1 }

    # readline — returns next line or undef
    sub getline {
        my ($self) = @_;
        return undef if $self->{closed};
        return shift @{ $self->{lines} };
    }

    # make <$sock> work via overloaded <>
    use overload '<>' => \&getline, fallback => 1;
}

# =============================================================================
# whois_query: round-robin iteration
# =============================================================================

subtest 'whois_query iterates sources until a match' => sub {

    # Mock whois_connect to always succeed with a fake socket
    $mock_iana->redefine(
        whois_connect => sub { FakeSocket->new([]) },
    );

    my $queried_sources = [];

    $mock_iana->redefine(
        source_connect => sub {
            my ( $self, $source_name ) = @_;
            push @$queried_sources, $source_name;

            # Only 'lacnic' returns a result
            if ( $source_name eq 'lacnic' ) {
                $self->{query_sub} = sub {
                    return (
                        country  => 'BR',
                        netname  => 'TEST-NET',
                        descr    => 'Test Network',
                        inetnum  => '200.0.0.0 - 200.0.0.255',
                        cidr     => '200.0.0.0/24',
                        owner    => 'Test Corp',
                        permission => 'allowed',
                        fullinfo => "inetnum: 200.0.0.0 - 200.0.0.255\n",
                    );
                };
                return FakeSocket->new([]);
            }

            # Other sources: return a connected socket but empty query
            $self->{query_sub} = sub { return () };
            return FakeSocket->new([]);
        },
    );

    my $iana = Net::Whois::IANA->new;
    my $result = $iana->whois_query( -ip => '200.0.0.1' );

    ok $result && keys %$result, 'got a result';
    is $result->{country}, 'BR', 'country from lacnic';
    is $result->{server}, 'LACNIC', 'server set to uppercase source name';

    # Should have queried arin, ripe, apnic before hitting lacnic
    is $queried_sources, [qw(arin ripe apnic lacnic)],
        'iterated sources in DEFAULT_SOURCE_ORDER until match';

    $mock_iana->unmock_all;
};

# =============================================================================
# whois_query: first match wins
# =============================================================================

subtest 'whois_query stops at first successful source' => sub {

    my $queried_sources = [];

    $mock_iana->redefine(
        source_connect => sub {
            my ( $self, $source_name ) = @_;
            push @$queried_sources, $source_name;

            # arin returns a result immediately
            $self->{query_sub} = sub {
                return (
                    country    => 'US',
                    netname    => 'GOOGLE',
                    descr      => 'Google LLC',
                    orgname    => 'Google LLC',
                    netrange   => '8.8.8.0 - 8.8.8.255',
                    cidr       => '8.8.8.0/24',
                    orgid      => 'GOGL',
                    nettype    => 'Direct Allocation',
                    permission => 'allowed',
                    fullinfo   => "OrgName: Google LLC\n",
                );
            };
            return FakeSocket->new([]);
        },
    );

    my $iana = Net::Whois::IANA->new;
    $iana->whois_query( -ip => '8.8.8.8' );

    is $queried_sources, ['arin'],
        'stopped after first source returned data';
    is $iana->country(), 'US', 'accessor works after query';

    $mock_iana->unmock_all;
};

# =============================================================================
# whois_query: permission denied skips to next source
# =============================================================================

subtest 'whois_query skips permission denied sources' => sub {

    my $queried_sources = [];

    $mock_iana->redefine(
        source_connect => sub {
            my ( $self, $source_name ) = @_;
            push @$queried_sources, $source_name;

            if ( $source_name eq 'arin' ) {
                $self->{query_sub} = sub {
                    return ( permission => 'denied', fullinfo => 'denied' );
                };
            }
            elsif ( $source_name eq 'ripe' ) {
                $self->{query_sub} = sub {
                    return (
                        country    => 'NL',
                        netname    => 'RIPE-NCC',
                        inetnum    => '193.0.0.0 - 193.0.0.255',
                        cidr       => ['193.0.0.0/24'],
                        permission => 'allowed',
                        fullinfo   => "inetnum: 193.0.0.0 - 193.0.0.255\n",
                    );
                };
            }
            else {
                $self->{query_sub} = sub { return () };
            }

            return FakeSocket->new([]);
        },
    );

    my $iana = Net::Whois::IANA->new;
    my $warnings = warnings {
        $iana->whois_query( -ip => '193.0.0.1' );
    };

    is $iana->country(), 'NL', 'fell through to ripe after arin denied';
    is $queried_sources, [qw(arin ripe)], 'queried arin then ripe';
    ok( ( grep { /permission denied/ } @$warnings ), 'warned about permission denied' );

    $mock_iana->unmock_all;
};

# =============================================================================
# whois_query: no match returns empty hashref
# =============================================================================

subtest 'whois_query returns empty hash when all sources fail' => sub {

    $mock_iana->redefine(
        source_connect => sub {
            my ( $self, $source_name ) = @_;
            $self->{query_sub} = sub { return () };
            return FakeSocket->new([]);
        },
    );

    my $iana   = Net::Whois::IANA->new;
    my $result = $iana->whois_query( -ip => '10.0.0.1' );

    is $result, {}, 'returns empty hashref when no source matches';
    is $iana->country(), undef, 'accessor returns undef';

    $mock_iana->unmock_all;
};

# =============================================================================
# whois_query: connection failure skips to next source
# =============================================================================

subtest 'whois_query handles connection failure gracefully' => sub {

    my $queried_sources = [];

    $mock_iana->redefine(
        source_connect => sub {
            my ( $self, $source_name ) = @_;
            push @$queried_sources, $source_name;

            # First two sources fail to connect
            return undef if $source_name eq 'arin' || $source_name eq 'ripe';

            # apnic succeeds
            $self->{query_sub} = sub {
                return (
                    country    => 'JP',
                    netname    => 'APNIC-NET',
                    inetnum    => '1.0.0.0 - 1.0.0.255',
                    cidr       => ['1.0.0.0/24'],
                    permission => 'allowed',
                    fullinfo   => "inetnum: 1.0.0.0\n",
                );
            };
            return FakeSocket->new([]);
        },
    );

    my $iana = Net::Whois::IANA->new;
    my $warnings = warnings {
        $iana->whois_query( -ip => '1.0.0.1' );
    };

    is $iana->country(), 'JP', 'got result from apnic after failures';

    # arin and ripe were attempted (connection failed), then apnic succeeded
    ok scalar @$queried_sources >= 3, 'tried multiple sources';

    $mock_iana->unmock_all;
};

# =============================================================================
# whois_query: -whois restricts to single source
# =============================================================================

subtest 'whois_query with -whois restricts source' => sub {

    my $connected_sources = [];

    $mock_iana->redefine(
        source_connect => sub {
            my ( $self, $source_name ) = @_;
            # Let real source_connect check if source exists
            return undef unless $self->{source}{$source_name};
            push @$connected_sources, $source_name;
            $self->{query_sub} = sub {
                return (
                    country    => 'DE',
                    netname    => 'RIPE-TEST',
                    inetnum    => '5.0.0.0 - 5.0.0.255',
                    cidr       => ['5.0.0.0/24'],
                    permission => 'allowed',
                    fullinfo   => "test\n",
                );
            };
            return FakeSocket->new([]);
        },
    );

    my $iana = Net::Whois::IANA->new;
    $iana->whois_query( -ip => '5.0.0.1', -whois => 'ripe' );

    is $iana->server(), 'RIPE', 'server matches restricted source';
    is $connected_sources, ['ripe'], 'only ripe was connected (others not in source)';

    $mock_iana->unmock_all;
};

# =============================================================================
# whois_query: post_process_query integrates abuse extraction
# =============================================================================

subtest 'whois_query applies post_process_query' => sub {

    $mock_iana->redefine(
        source_connect => sub {
            my ( $self, $source_name ) = @_;
            $self->{query_sub} = sub {
                return (
                    country    => 'US',
                    netname    => 'ABUSE-TEST',
                    inetnum    => '10.0.0.0 - 10.0.0.255',
                    cidr       => '10.0.0.0/24,10.0.1.0/24',
                    permission => 'allowed',
                    fullinfo   => "abuse-email: abuse\@example.com\nOrgName: Test\n",
                );
            };
            return FakeSocket->new([]);
        },
    );

    my $iana = Net::Whois::IANA->new;
    $iana->whois_query( -ip => '10.0.0.1' );

    # post_process_query splits comma-separated CIDR into arrayref
    is ref $iana->cidr(), 'ARRAY', 'cidr converted to arrayref';
    is $iana->cidr(), ['10.0.0.0/24', '10.0.1.0/24'], 'cidr split correctly';

    # abuse extracted from fullinfo
    like $iana->abuse(), qr/abuse\@example\.com/, 'abuse email extracted from fullinfo';

    $mock_iana->unmock_all;
};

# =============================================================================
# source_connect: query_sub assignment
# =============================================================================

subtest 'source_connect assigns query_sub from server ref' => sub {

    my $custom_query = sub { return ( test => 1 ) };

    my $iana = Net::Whois::IANA->new;
    $iana->{source} = {
        custom => [ ['whois.example.com', 43, 30, $custom_query] ],
    };

    $mock_iana->redefine(
        whois_connect => sub { FakeSocket->new([]) },
    );

    my $sock = $iana->source_connect('custom');
    ok $sock, 'got a socket back';
    is $iana->{query_sub}, $custom_query, 'custom query sub assigned';
    is $iana->{whois_host}, 'whois.example.com', 'whois_host set';

    $mock_iana->unmock_all;
};

subtest 'source_connect falls back to default_query when no code ref' => sub {

    my $iana = Net::Whois::IANA->new;
    $iana->{source} = {
        nocode => [ ['whois.example.com', 43, 30, undef] ],
    };

    $mock_iana->redefine(
        whois_connect => sub { FakeSocket->new([]) },
    );

    $iana->source_connect('nocode');
    is $iana->{query_sub}, \&Net::Whois::IANA::default_query,
        'falls back to default_query when no code ref provided';

    $mock_iana->unmock_all;
};

subtest 'source_connect tries multiple servers in order' => sub {

    my $connect_attempts = [];

    $mock_iana->redefine(
        whois_connect => sub {
            my ($server_ref) = @_;
            my $host = ref $server_ref ? $server_ref->[0] : $server_ref;
            push @$connect_attempts, $host;
            # First server fails, second succeeds
            return $host eq 'backup.example.com' ? FakeSocket->new([]) : 0;
        },
    );

    my $iana = Net::Whois::IANA->new;
    $iana->{source} = {
        multi => [
            ['primary.example.com', 43, 30, undef],
            ['backup.example.com',  43, 30, undef],
        ],
    };

    my $sock = $iana->source_connect('multi');
    ok $sock, 'connected via backup server';
    is $connect_attempts, ['primary.example.com', 'backup.example.com'],
        'tried primary first, then backup';
    is $iana->{whois_host}, 'backup.example.com', 'whois_host set to backup';

    $mock_iana->unmock_all;
};

subtest 'source_connect returns undef when all servers fail' => sub {

    $mock_iana->redefine(
        whois_connect => sub { 0 },
    );

    my $iana = Net::Whois::IANA->new;
    $iana->{source} = {
        dead => [ ['dead1.example.com', 43, 30, undef] ],
    };

    my $sock = $iana->source_connect('dead');
    is $sock, undef, 'returns undef when no server connects';

    $mock_iana->unmock_all;
};

# =============================================================================
# is_mine: CIDR padding and validation
# =============================================================================

subtest 'is_mine' => sub {

    my $mock_cidr = Test::MockModule->new('Net::CIDR');
    my @cidrlookup_args;

    $mock_cidr->redefine(
        cidrlookup => sub {
            @cidrlookup_args = @_;
            # Simple prefix match for testing
            my ( $ip, @ranges ) = @_;
            return 1 if grep { $ip =~ /^10\./ && /^10\./ } @ranges;
            return 0;
        },
    );

    subtest 'uses query cidr when no explicit ranges given' => sub {
        my $iana = Net::Whois::IANA->new;
        $iana->{QUERY} = { cidr => ['10.0.0.0/8'] };

        ok $iana->is_mine('10.1.2.3'), 'IP in range returns true';
        is $cidrlookup_args[0], '10.1.2.3', 'IP passed to cidrlookup';
    };

    subtest 'uses explicit cidr ranges when provided' => sub {
        my $iana = Net::Whois::IANA->new;
        $iana->{QUERY} = { cidr => ['192.168.0.0/16'] };

        $iana->is_mine( '10.0.0.1', '10.0.0.0/24' );
        is $cidrlookup_args[1], '10.0.0.0/24', 'explicit range used instead of query cidr';
    };

    subtest 'rejects invalid IP' => sub {
        my $iana = Net::Whois::IANA->new;
        is $iana->is_mine('not-an-ip'), 0, 'returns 0 for invalid IP';
    };

    subtest 'handles short CIDR notation with padding' => sub {
        my $iana = Net::Whois::IANA->new;
        $iana->{QUERY} = { cidr => ['10.0/16'] };

        # is_mine pads short CIDRs: 10.0/16 -> 10.0.0.0/16
        $iana->is_mine('10.0.0.1');
        like $cidrlookup_args[1], qr/^10\.0\.0\.0\/16/, 'short CIDR padded with .0';
    };

    subtest 'handles space-separated CIDR values' => sub {
        my $iana = Net::Whois::IANA->new;
        $iana->{QUERY} = { cidr => ['10.0.0.0/24 10.1.0.0/24'] };

        $iana->is_mine('10.0.0.1');
        # split on whitespace produces two separate ranges
        ok @cidrlookup_args > 2, 'space-separated CIDRs expanded';
    };

    subtest 'handles undef entries in cidr array' => sub {
        my $iana = Net::Whois::IANA->new;
        $iana->{QUERY} = { cidr => [undef, '10.0.0.0/24'] };

        # Should not die on undef entries
        ok lives { $iana->is_mine('10.0.0.1') }, 'handles undef in cidr array';
    };

    subtest 'returns 0 when no cidr data and no explicit ranges' => sub {
        my $iana = Net::Whois::IANA->new;
        $iana->{QUERY} = {};

        is $iana->is_mine('10.0.0.1'), 0, 'returns 0 when no cidr data';
    };

    $mock_cidr->unmock_all;
};

done_testing;
