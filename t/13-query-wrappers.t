#!/usr/bin/env perl

use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;

use Net::Whois::IANA;

# =============================================================================
# Integration tests for *_query wrapper functions.
# These compose _read_query + _process_query and are the actual entry points
# called by source_connect/whois_query.  Individual components are tested in
# t/07-query-processing.t and t/09-read-query.t; these tests verify the
# integration: data flows correctly from socket parse through processing to
# the final hash returned to whois_query.
# =============================================================================

# --- FakeHandle: tied filehandle for socket simulation ---
{
    package FakeHandle;
    use Tie::Handle;
    use base 'Tie::Handle';

    sub TIEHANDLE {
        my ( $class, $lines ) = @_;
        return bless { lines => [ @{ $lines || [] } ], closed => 0 }, $class;
    }
    sub PRINT    { 1 }
    sub READLINE {
        my ($self) = @_;
        return undef if $self->{closed};
        return shift @{ $self->{lines} };
    }
    sub CLOSE { $_[0]->{closed} = 1; return 1 }
}

my $fake_sock_counter = 0;

sub fake_sock {
    my ($lines) = @_;
    my $name = "FakeHandle::SOCK_" . ++$fake_sock_counter;
    no strict 'refs';
    tie *{$name}, 'FakeHandle', $lines;
    return \*{$name};
}

# =============================================================================
# ripe_query
# =============================================================================

subtest 'ripe_query: valid response with country' => sub {
    my $sock = fake_sock([
        "% RIPE Database query\n",
        "inetnum:        193.0.0.0 - 193.0.7.255\n",
        "netname:        RIPE-NCC\n",
        "descr:          RIPE Network Coordination Centre\n",
        "country:        NL\n",
        "source:         RIPE\n",
    ]);

    my %q = Net::Whois::IANA::ripe_query( $sock, '193.0.0.135' );

    is $q{permission}, 'allowed', 'permission set';
    is $q{country},    'NL',      'country preserved';
    is ref $q{cidr},   'ARRAY',   'cidr is arrayref';
    ok scalar @{ $q{cidr} }, 'cidr has entries';
};

subtest 'ripe_query: missing country returns empty' => sub {
    # ripe_query has a special filter: return () unless defined $query{country}
    my $sock = fake_sock([
        "inetnum:        10.0.0.0 - 10.255.255.255\n",
        "netname:        TEST-NET\n",
        "descr:          Test network\n",
        "source:         RIPE\n",
    ]);

    my %q = Net::Whois::IANA::ripe_query( $sock, '10.0.0.1' );

    is scalar keys %q, 0, 'returns empty when country is missing';
};

subtest 'ripe_query: IANA-BLK with country still rejected' => sub {
    my $sock = fake_sock([
        "inetnum:        0.0.0.0 - 255.255.255.255\n",
        "netname:        IANA-BLK\n",
        "country:        EU\n",
        "source:         RIPE\n",
    ]);

    my %q = Net::Whois::IANA::ripe_query( $sock, '10.0.0.1' );

    is scalar keys %q, 0, 'IANA-BLK rejected even with country present';
};

subtest 'ripe_query: inet6num works end-to-end' => sub {
    my $sock = fake_sock([
        "inet6num:       2001:0DB8:: - 2001:0DB8:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\n",
        "netname:        TEST-V6\n",
        "country:        DE\n",
        "source:         RIPE\n",
    ]);

    my %q = Net::Whois::IANA::ripe_query( $sock, '2001:db8::1' );

    is $q{permission}, 'allowed', 'permission set';
    is $q{country},    'DE',      'country preserved';
    is ref $q{cidr},   'ARRAY',   'cidr is arrayref';
    like $q{cidr}[0], qr/2001/i, 'cidr contains IPv6 prefix';
};

# =============================================================================
# apnic_query
# =============================================================================

subtest 'apnic_query: valid response' => sub {
    my $sock = fake_sock([
        "% Information related to '1.0.0.0 - 1.0.0.255'\n",
        "inetnum:        1.0.0.0 - 1.0.0.255\n",
        "netname:        APNIC-LABS\n",
        "descr:          APNIC Research\n",
        "country:        AU\n",
        "source:         APNIC\n",
    ]);

    my %q = Net::Whois::IANA::apnic_query( $sock, '1.0.0.1' );

    is $q{permission}, 'allowed', 'permission set';
    is $q{country},    'AU',      'country preserved';
    is ref $q{cidr},   'ARRAY',   'cidr is arrayref';
};

subtest 'apnic_query: not-administered returns empty' => sub {
    my $sock = fake_sock([
        "% Information related to '10.0.0.0 - 10.255.255.255'\n",
        "inetnum:        10.0.0.0 - 10.255.255.255\n",
        "remarks:        address range is not administered by APNIC\n",
        "country:        AU\n",
    ]);

    my %q = Net::Whois::IANA::apnic_query( $sock, '10.0.0.1' );

    is scalar keys %q, 0, 'not-administered returns empty';
};

# =============================================================================
# arin_query
# =============================================================================

subtest 'arin_query: valid response' => sub {
    my $sock = fake_sock([
        "#\n",
        "# ARIN WHOIS data\n",
        "#\n",
        "OrgName:        Google LLC\n",
        "OrgId:          GOGL\n",
        "NetRange:       8.8.8.0 - 8.8.8.255\n",
        "CIDR:           8.8.8.0/24\n",
        "NetType:        Direct Allocation\n",
        "Country:        US\n",
    ]);

    my %q = Net::Whois::IANA::arin_query( $sock, '8.8.8.8' );

    is $q{permission}, 'allowed',           'permission set';
    is $q{descr},      'Google LLC',        'descr mapped from orgname';
    is $q{source},     'ARIN',              'source set';
    is $q{inetnum},    '8.8.8.0 - 8.8.8.255', 'inetnum from netrange';
    is ref $q{cidr},   'ARRAY',             'cidr is arrayref';
    is $q{cidr}[0],    '8.8.8.0/24',        'cidr value correct';
};

subtest 'arin_query: RIPE orgid redirects (returns empty)' => sub {
    my $sock = fake_sock([
        "OrgName:        RIPE NCC\n",
        "OrgId:          RIPE\n",
        "NetRange:       193.0.0.0 - 193.0.7.255\n",
        "CIDR:           193.0.0.0/21\n",
    ]);

    my %q = Net::Whois::IANA::arin_query( $sock, '193.0.0.1' );

    is scalar keys %q, 0, 'RIPE orgid causes empty return';
};

subtest 'arin_query: no match returns empty' => sub {
    my $sock = fake_sock([
        "#\n",
        "# No match found for 192.0.2.1.\n",
        "#\n",
    ]);

    my %q = Net::Whois::IANA::arin_query( $sock, '192.0.2.1' );

    is scalar keys %q, 0, 'no match returns empty';
};

# =============================================================================
# lacnic_query
# =============================================================================

subtest 'lacnic_query: valid response' => sub {
    my $sock = fake_sock([
        "% Joint Whois - whois.lacnic.net\n",
        "% lacnic resource:\n",
        "inetnum:     200.0.0.0/16\n",
        "owner:       Telefonica Brasil\n",
        "ownerid:     TELEPHO\n",
        "country:     BR\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_query( $sock, '200.0.0.1' );

    is $q{permission}, 'allowed',            'permission set';
    is $q{descr},      'Telefonica Brasil',  'descr from owner';
    is $q{source},     'LACNIC',             'source set';
    is $q{country},    'BR',                 'country preserved';
};

subtest 'lacnic_query: non-lacnic resource returns empty' => sub {
    my $sock = fake_sock([
        "% Joint Whois\n",
        "% arin resource:\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_query( $sock, '8.8.8.8' );

    is scalar keys %q, 0, 'non-LACNIC resource returns empty';
};

subtest 'lacnic_query: inet6num works end-to-end' => sub {
    my $sock = fake_sock([
        "% lacnic resource:\n",
        "inet6num:    2001:0db8::/32\n",
        "owner:       NIC.br\n",
        "ownerid:     NICBR\n",
        "country:     BR\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_query( $sock, '2001:db8::1' );

    is $q{permission}, 'allowed', 'permission set';
    is ref $q{cidr},   'ARRAY',   'cidr is arrayref';
    like $q{cidr}[0], qr/2001/i, 'cidr contains IPv6 prefix';
};

# =============================================================================
# afrinic_query
# =============================================================================

subtest 'afrinic_query: valid response' => sub {
    my $sock = fake_sock([
        "% AFRINIC query\n",
        "inetnum:        102.0.0.0 - 102.255.255.255\n",
        "netname:        AFRINIC-NET\n",
        "descr:          AFRINIC\n",
        "country:        ZA\n",
        "source:         AFRINIC\n",
    ]);

    my %q = Net::Whois::IANA::afrinic_query( $sock, '102.0.0.1' );

    is $q{permission}, 'allowed', 'permission set';
    is $q{country},    'ZA',      'country preserved';
    is ref $q{cidr},   'ARRAY',   'cidr is arrayref';
};

subtest 'afrinic_query: worldwide remarks returns empty' => sub {
    my $sock = fake_sock([
        "inetnum:        0.0.0.0 - 255.255.255.255\n",
        "remarks:        country is really worldwide\n",
        "country:        ZA\n",
    ]);

    my %q = Net::Whois::IANA::afrinic_query( $sock, '102.0.0.1' );

    is scalar keys %q, 0, 'worldwide remarks returns empty';
};

# =============================================================================
# jpnic_query
# =============================================================================

subtest 'jpnic_query: bracket-style response' => sub {
    my $sock = fake_sock([
        "a. [Network Number]  58.0.0.0/8\n",
        "b. [Network Name]    JPNIC-NET\n",
        "g. [Organization Name]  Japan NIC\n",
        "country:        JP\n",
    ]);

    my %q = Net::Whois::IANA::jpnic_query( $sock, '58.0.0.1' );

    is $q{permission}, 'allowed', 'permission set';
    is $q{source},     'JPNIC',   'source set';
    is ref $q{cidr},   'ARRAY',   'cidr is arrayref';
    is $q{cidr}[0],    '58.0.0.0/8', 'cidr from JPNIC bracket notation';
};

subtest 'jpnic_query: missing inetnum returns empty' => sub {
    my $sock = fake_sock([
        "netname:        JPNIC-NET\n",
        "country:        JP\n",
    ]);

    my %q = Net::Whois::IANA::jpnic_query( $sock, '58.0.0.1' );

    is scalar keys %q, 0, 'returns empty without inetnum';
};

# =============================================================================
# krnic_query
# =============================================================================

subtest 'krnic_query: response with ipv4 address field' => sub {
    # KRNIC sometimes uses 'ipv4 address' instead of 'inetnum'
    my $sock = fake_sock([
        "% KRNIC query\n",
        "ipv4 address:   59.0.0.0 - 59.25.255.255\n",
        "netname:        KRNIC-KR\n",
        "descr:          Korea Internet\n",
        "country:        KR\n",
    ]);

    my %q = Net::Whois::IANA::krnic_query( $sock, '59.0.0.1' );

    is $q{permission}, 'allowed', 'permission set';
    is $q{source},     'KRNIC',   'source set';
    is $q{inetnum},    '59.0.0.0 - 59.25.255.255', 'inetnum from ipv4 address field';
    is ref $q{cidr},   'ARRAY',   'cidr is arrayref';
};

subtest 'krnic_query: standard inetnum field' => sub {
    my $sock = fake_sock([
        "inetnum:        59.0.0.0 - 59.25.255.255\n",
        "netname:        KRNIC-KR\n",
        "country:        KR\n",
    ]);

    my %q = Net::Whois::IANA::krnic_query( $sock, '59.0.0.1' );

    is $q{permission}, 'allowed', 'permission set';
    is ref $q{cidr},   'ARRAY',   'cidr is arrayref';
};

# =============================================================================
# idnic_query
# =============================================================================

subtest 'idnic_query: valid response' => sub {
    my $sock = fake_sock([
        "% IDNIC query\n",
        "inetnum:        49.0.0.0 - 49.255.255.255\n",
        "netname:        IDNIC-NET\n",
        "descr:          Indonesia NIC\n",
        "country:        ID\n",
    ]);

    my %q = Net::Whois::IANA::idnic_query( $sock, '49.0.0.1' );

    is $q{permission}, 'allowed', 'permission set';
    is $q{source},     'IDNIC',   'source set';
    is ref $q{cidr},   'ARRAY',   'cidr is arrayref';
};

subtest 'idnic_query: missing inetnum returns empty' => sub {
    my $sock = fake_sock([
        "netname:        IDNIC-NET\n",
        "country:        ID\n",
    ]);

    my %q = Net::Whois::IANA::idnic_query( $sock, '49.0.0.1' );

    is scalar keys %q, 0, 'returns empty without inetnum';
};

# =============================================================================
# default_query (delegates to arin_query)
# =============================================================================

subtest 'default_query: delegates to arin_query' => sub {
    my $sock = fake_sock([
        "OrgName:        Test Org\n",
        "OrgId:          TEST\n",
        "NetRange:       10.0.0.0 - 10.0.0.255\n",
        "CIDR:           10.0.0.0/24\n",
        "NetType:        Direct Allocation\n",
        "Country:        US\n",
    ]);

    my %q = Net::Whois::IANA::default_query( $sock, '10.0.0.1' );

    is $q{permission}, 'allowed',   'permission set via arin delegation';
    is $q{descr},      'Test Org',  'descr from orgname (ARIN format)';
    is $q{source},     'ARIN',      'source is ARIN';
    is ref $q{cidr},   'ARRAY',     'cidr is arrayref';
};

done_testing;
