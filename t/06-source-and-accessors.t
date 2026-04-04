#!/usr/bin/env perl

use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;

use Net::Whois::IANA;

# =============================================================================
# Unit tests for set_source(), init_query(), and generated accessor methods.
# No network required.
# =============================================================================

# --- new ---

subtest 'constructor' => sub {
    my $iana = Net::Whois::IANA->new;
    isa_ok $iana, 'Net::Whois::IANA';
    is ref $iana, 'Net::Whois::IANA', 'blessed into correct class';
};

# --- set_source ---

subtest 'set_source' => sub {

    subtest 'known string source' => sub {
        my $iana = Net::Whois::IANA->new;
        is $iana->set_source('ripe'), 0, 'returns 0 for known source';
        is [ sort keys %{ $iana->{source} } ], ['ripe'], 'source set to ripe only';
    };

    subtest 'all known sources accepted' => sub {
        for my $name (qw(arin ripe apnic lacnic afrinic)) {
            my $iana = Net::Whois::IANA->new;
            is $iana->set_source($name), 0, "returns 0 for $name";
        }
    };

    subtest 'unknown string source' => sub {
        my $iana = Net::Whois::IANA->new;
        is $iana->set_source('bogus'), 1, 'returns 1 for unknown source';
    };

    subtest 'valid custom hashref source' => sub {
        my $iana   = Net::Whois::IANA->new;
        my %custom = (
            myserver => [ ['whois.example.com', 43, 30, undef] ],
        );
        is $iana->set_source(\%custom), 0, 'returns 0 for valid custom source';
        is $iana->{source}, \%custom, 'custom source stored';
    };

    subtest 'invalid custom source - not a hashref' => sub {
        my $iana = Net::Whois::IANA->new;
        is $iana->set_source( [1, 2, 3] ), 2, 'returns 2 for arrayref';
    };

    subtest 'invalid custom source - bad structure' => sub {
        my $iana = Net::Whois::IANA->new;
        is $iana->set_source( { bad => 'string' } ), 2, 'returns 2 for malformed hash';
    };

    subtest 'undef source sets all defaults' => sub {
        my $iana = Net::Whois::IANA->new;
        my $ret  = $iana->set_source(undef);
        is $ret, 0, 'returns 0 for undef';
        my @keys = sort keys %{ $iana->{source} };
        is \@keys, [sort keys %Net::Whois::IANA::IANA], 'all default sources loaded';
    };
};

# --- init_query ---

subtest 'init_query' => sub {

    subtest 'rejects invalid IP' => sub {
        my $iana = Net::Whois::IANA->new;
        my $warnings = warnings { $iana->init_query(-ip => 'not-an-ip') };
        ok scalar @$warnings, 'warns on invalid IP';
        like $warnings->[0], qr/Method usage/, 'usage message shown';
    };

    subtest 'rejects missing IP' => sub {
        my $iana = Net::Whois::IANA->new;
        my $warnings = warnings { $iana->init_query() };
        ok scalar @$warnings, 'warns on missing IP';
    };

    subtest 'accepts valid IPv4' => sub {
        my $iana = Net::Whois::IANA->new;
        my $warnings = warnings { $iana->init_query(-ip => '8.8.8.8') };
        is $warnings, [], 'no warnings for valid IPv4';
        ok exists $iana->{source}, 'source configured';
    };

    subtest 'accepts valid IPv6' => sub {
        my $iana = Net::Whois::IANA->new;
        my $warnings = warnings { $iana->init_query(-ip => '2001:db8::1') };
        is $warnings, [], 'no warnings for valid IPv6';
    };

    subtest 'rejects unknown -whois server' => sub {
        my $iana = Net::Whois::IANA->new;
        my $warnings = warnings { $iana->init_query(-ip => '8.8.8.8', -whois => 'bogus') };
        ok scalar @$warnings, 'warns on unknown whois server';
        like $warnings->[0], qr/Unknown whois server/, 'proper warning message';
    };

    subtest 'accepts known -whois server' => sub {
        my $iana = Net::Whois::IANA->new;
        my $warnings = warnings { $iana->init_query(-ip => '8.8.8.8', -whois => 'ripe') };
        is $warnings, [], 'no warnings for known whois server';
        is [ sort keys %{ $iana->{source} } ], ['ripe'], 'source restricted to ripe';
    };

    subtest 'rejects invalid custom -mywhois source' => sub {
        my $iana = Net::Whois::IANA->new;
        my $result;
        my $warnings = warnings {
            $result = $iana->init_query(-ip => '8.8.8.8', -mywhois => { bad => 'string' })
        };
        ok scalar @$warnings, 'warns on invalid custom source';
        like $warnings->[0], qr/Custom sources must be of form/, 'proper warning message';
        is $result, {}, 'returns empty hashref on invalid custom source';
    };
};

# --- accessor methods ---

subtest 'accessor methods' => sub {

    my %query_data = (
        country  => 'US',
        netname  => 'GOOGLE',
        descr    => 'Google LLC',
        status   => 'Direct Allocation',
        source   => 'ARIN',
        server   => 'ARIN',
        inetnum  => '8.8.8.0 - 8.8.8.255',
        inet6num => undef,
        cidr     => ['8.8.8.0/24'],
        abuse    => 'abuse@google.com',
        fullinfo => "OrgName: Google LLC\n",
    );

    my $iana = Net::Whois::IANA->new;
    $iana->{QUERY} = \%query_data;

    subtest 'each accessor returns its field' => sub {
        is $iana->country(), 'US',                  'country';
        is $iana->netname(), 'GOOGLE',              'netname';
        is $iana->descr(),   'Google LLC',          'descr';
        is $iana->status(),  'Direct Allocation',   'status';
        is $iana->source(),  'ARIN',                'source';
        is $iana->server(),  'ARIN',                'server';
        is $iana->inetnum(), '8.8.8.0 - 8.8.8.255', 'inetnum';
        is $iana->cidr(),    ['8.8.8.0/24'],        'cidr';
        is $iana->abuse(),   'abuse@google.com',    'abuse';
        like $iana->fullinfo(), qr/Google LLC/,     'fullinfo';
    };

    subtest 'desc is alias for descr' => sub {
        is $iana->desc(), $iana->descr(), 'desc() == descr()';
    };

    subtest 'accessors return undef when no QUERY' => sub {
        my $empty = Net::Whois::IANA->new;
        is $empty->country(), undef, 'country undef without query';
        is $empty->netname(), undef, 'netname undef without query';
        is $empty->cidr(),    undef, 'cidr undef without query';
    };

    subtest 'accessor dies on non-method call' => sub {
        ok dies { Net::Whois::IANA::country('not-a-ref') },
            'dies when called as function with non-ref';
    };
};

done_testing;
