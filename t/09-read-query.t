#!/usr/bin/env perl

use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;

use Net::Whois::IANA;

# =============================================================================
# Unit tests for *_read_query functions.
# These test the core parsing logic with fake sockets — no network required.
# =============================================================================

# --- FakeHandle: tied filehandle that yields lines and absorbs writes ---
{
    package FakeHandle;
    use Tie::Handle;
    use base 'Tie::Handle';

    sub TIEHANDLE {
        my ( $class, $lines ) = @_;
        return bless { lines => [ @{ $lines || [] } ], closed => 0 }, $class;
    }
    sub PRINT    { 1 }    # absorb query writes (e.g. "print $sock '-r $ip\n'")
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
# ripe_read_query
# =============================================================================

subtest 'ripe_read_query: standard response' => sub {
    my $sock = fake_sock([
        "% This is the RIPE Database query service.\n",
        "% Information related to '193.0.0.0 - 193.0.7.255'\n",
        "\n",
        "inetnum:        193.0.0.0 - 193.0.7.255\n",
        "netname:        RIPE-NCC\n",
        "descr:          RIPE Network Coordination Centre\n",
        "country:        NL\n",
        "status:         ASSIGNED PA\n",
        "source:         RIPE\n",
    ]);

    my %q = Net::Whois::IANA::ripe_read_query( $sock, '193.0.0.135' );

    is $q{inetnum}, '193.0.0.0 - 193.0.7.255', 'inetnum parsed';
    is $q{netname}, 'RIPE-NCC', 'netname parsed';
    is $q{country}, 'NL', 'country parsed';
    is $q{status},  'ASSIGNED PA', 'status parsed';
    is $q{source},  'RIPE', 'source parsed';
    like $q{fullinfo}, qr/193\.0\.0\.0/, 'fullinfo contains raw output';
};

subtest 'ripe_read_query: skips comments and non-key lines' => sub {
    my $sock = fake_sock([
        "% This is a comment\n",
        "# Another comment\n",
        "just some text without colon\n",
        "netname:        TEST-NET\n",
        "country:        DE\n",
    ]);

    my %q = Net::Whois::IANA::ripe_read_query( $sock, '10.0.0.1' );

    is $q{netname}, 'TEST-NET', 'parsed field after comments';
    is $q{country}, 'DE', 'country parsed';
    ok !defined $q{'just some text without colon'}, 'non-colon lines skipped';
};

subtest 'ripe_read_query: appends multiple values for same field' => sub {
    my $sock = fake_sock([
        "descr:          First line\n",
        "descr:          Second line\n",
        "country:        FR\n",
    ]);

    my %q = Net::Whois::IANA::ripe_read_query( $sock, '10.0.0.1' );

    is $q{descr}, 'First line Second line', 'multiple values joined with space';
};

subtest 'ripe_read_query: permission denied on ERROR:201' => sub {
    my $sock = fake_sock([
        "% This is the RIPE Database query service.\n",
        "%ERROR:201: access denied\n",
    ]);

    my %q = Net::Whois::IANA::ripe_read_query( $sock, '10.0.0.1' );

    is $q{permission}, 'denied', 'permission set to denied';
    ok tied(*$sock)->{closed}, 'socket was closed';
};

subtest 'ripe_read_query: strips trailing whitespace from values' => sub {
    my $sock = fake_sock([
        "netname:        TRAILING-WS   \n",
        "country:        US\n",
    ]);

    my %q = Net::Whois::IANA::ripe_read_query( $sock, '10.0.0.1' );

    is $q{netname}, 'TRAILING-WS', 'trailing whitespace stripped';
};

# =============================================================================
# apnic_read_query
# =============================================================================

subtest 'apnic_read_query: standard response' => sub {
    my $sock = fake_sock([
        "% Information related to '1.0.0.0 - 1.0.0.255'\n",
        "\n",
        "inetnum:        1.0.0.0 - 1.0.0.255\n",
        "netname:        APNIC-TEST\n",
        "descr:          Test Network\n",
        "country:        AU\n",
        "source:         APNIC\n",
    ]);

    my %q = Net::Whois::IANA::apnic_read_query( $sock, '1.0.0.1' );

    is $q{inetnum}, '1.0.0.0 - 1.0.0.255', 'inetnum parsed';
    is $q{netname}, 'APNIC-TEST', 'netname parsed';
    is $q{country}, 'AU', 'country parsed';
};

subtest 'apnic_read_query: skips 0.0.0.0 block' => sub {
    my $sock = fake_sock([
        "% Information related to '0.0.0.0 - 255.255.255.255'\n",
        "inetnum:        0.0.0.0 - 255.255.255.255\n",
        "netname:        SHOULD-SKIP\n",
        "country:        ZZ\n",
        "% Information related to '1.0.0.0 - 1.0.0.255'\n",
        "inetnum:        1.0.0.0 - 1.0.0.255\n",
        "netname:        REAL-NET\n",
        "country:        JP\n",
    ]);

    my %q = Net::Whois::IANA::apnic_read_query( $sock, '1.0.0.1' );

    is $q{netname}, 'REAL-NET', '0.0.0.0 block skipped, real data parsed';
    is $q{country}, 'JP', 'country from real block';
};

subtest 'apnic_read_query: permission denied on %201' => sub {
    my $sock = fake_sock([
        "%201 access denied\n",
    ]);

    my %q = Net::Whois::IANA::apnic_read_query( $sock, '1.0.0.1' );

    is $q{permission}, 'denied', 'permission set to denied';
    ok tied(*$sock)->{closed}, 'socket was closed';
};

subtest 'apnic_read_query: inetnum resets query accumulator' => sub {
    # When a second inetnum line appears, the query hash resets
    # but fullinfo carries over, and old fields become fallbacks
    my $sock = fake_sock([
        "% Information related to '1.0.0.0 - 1.255.255.255'\n",
        "inetnum:        1.0.0.0 - 1.255.255.255\n",
        "netname:        BROAD-NET\n",
        "descr:          Broad allocation\n",
        "country:        AU\n",
        "source:         APNIC\n",
        "% Information related to '1.0.0.0 - 1.0.0.255'\n",
        "inetnum:        1.0.0.0 - 1.0.0.255\n",
        "netname:        SPECIFIC-NET\n",
        "country:        JP\n",
    ]);

    my %q = Net::Whois::IANA::apnic_read_query( $sock, '1.0.0.1' );

    is $q{inetnum}, '1.0.0.0 - 1.0.0.255', 'specific inetnum used';
    is $q{netname}, 'SPECIFIC-NET', 'specific netname used';
    is $q{country}, 'JP', 'first country from specific block used';
    # descr and source should fall back from the broad block
    is $q{descr}, 'Broad allocation', 'descr falls back from previous block';
    is $q{source}, 'APNIC', 'source falls back from previous block';
};

subtest 'apnic_read_query: keeps first country value' => sub {
    my $sock = fake_sock([
        "inetnum:        1.0.0.0 - 1.0.0.255\n",
        "country:        JP\n",
        "country:        AU\n",
        "netname:        TEST\n",
    ]);

    my %q = Net::Whois::IANA::apnic_read_query( $sock, '1.0.0.1' );

    is $q{country}, 'JP', 'first country kept, second ignored';
};

# =============================================================================
# arin_read_query
# =============================================================================

subtest 'arin_read_query: standard response' => sub {
    my $sock = fake_sock([
        "#\n",
        "# ARIN WHOIS data and services\n",
        "#\n",
        "NetRange:       8.8.8.0 - 8.8.8.255\n",
        "CIDR:           8.8.8.0/24\n",
        "NetName:        LVLT-GOGL-8-8-8\n",
        "NetHandle:      NET-8-8-8-0-2\n",
        "NetType:        Direct Allocation\n",
        "OrgName:        Google LLC\n",
        "OrgId:          GOGL\n",
        "Country:        US\n",
    ]);

    my %q = Net::Whois::IANA::arin_read_query( $sock, '8.8.8.8' );

    is $q{netrange}, '8.8.8.0 - 8.8.8.255', 'netrange parsed';
    is $q{cidr},     '8.8.8.0/24', 'cidr parsed';
    is $q{netname},  'LVLT-GOGL-8-8-8', 'netname parsed (lowercased)';
    is $q{orgname},  'Google LLC', 'orgname parsed';
    is $q{orgid},    'GOGL', 'orgid parsed';
    is $q{country},  'US', 'country parsed';
};

subtest 'arin_read_query: OrgName resets accumulator' => sub {
    my $sock = fake_sock([
        "NetRange:       8.8.8.0 - 8.8.8.255\n",
        "CIDR:           8.8.8.0/24\n",
        "NetType:        Direct Allocation\n",
        "OrgName:        Google LLC\n",
        "OrgId:          GOGL\n",
        "Country:        US\n",
    ]);

    my %q = Net::Whois::IANA::arin_read_query( $sock, '8.8.8.8' );

    # After OrgName resets, cidr/netrange from first block should still be accessible
    # via fallback from %tmp
    is $q{orgname}, 'Google LLC', 'orgname from second block';
    is $q{cidr},    '8.8.8.0/24', 'cidr carried over from first block';
};

subtest 'arin_read_query: CustName overrides orgname' => sub {
    my $sock = fake_sock([
        "CustName:       Customer Corp\n",
        "NetRange:       10.0.0.0 - 10.0.0.255\n",
        "Country:        CA\n",
    ]);

    my %q = Net::Whois::IANA::arin_read_query( $sock, '10.0.0.1' );

    is $q{orgname}, 'Customer Corp', 'custname copied to orgname';
};

subtest 'arin_read_query: no match returns empty' => sub {
    my $sock = fake_sock([
        "# ARIN WHOIS\n",
        "No match found for 192.0.2.1\n",
    ]);

    my %q = Net::Whois::IANA::arin_read_query( $sock, '192.0.2.1' );

    is scalar keys %q, 0, 'returns empty on no match';
    ok tied(*$sock)->{closed}, 'socket was closed on no match';
};

subtest 'arin_read_query: permission denied on #201' => sub {
    my $sock = fake_sock([
        "#201 access denied\n",
    ]);

    my %q = Net::Whois::IANA::arin_read_query( $sock, '10.0.0.1' );

    is $q{permission}, 'denied', 'permission denied detected';
    ok tied(*$sock)->{closed}, 'socket was closed';
};

subtest 'arin_read_query: skips comment and non-colon lines' => sub {
    my $sock = fake_sock([
        "# This is a comment\n",
        "Some text without colon\n",
        "OrgName:        Test Org\n",
        "Country:        US\n",
    ]);

    my %q = Net::Whois::IANA::arin_read_query( $sock, '10.0.0.1' );

    is $q{orgname}, 'Test Org', 'field after non-colon lines parsed';
};

# =============================================================================
# lacnic_read_query
# =============================================================================

subtest 'lacnic_read_query: standard response' => sub {
    my $sock = fake_sock([
        "% Joint Whois - whois.lacnic.net\n",
        "% lacnic resource:\n",
        "\n",
        "inetnum:     200.0.0.0/24\n",
        "owner:       Test Corp BR\n",
        "ownerid:     BR-TEST-LACNIC\n",
        "country:     BR\n",
        "nserver:     ns1.test.br\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_read_query( $sock, '200.0.0.1' );

    is $q{inetnum}, '200.0.0.0/24', 'inetnum parsed';
    is $q{owner},   'Test Corp BR', 'owner parsed';
    is $q{ownerid}, 'BR-TEST-LACNIC', 'ownerid parsed';
    is $q{country}, 'BR', 'country parsed';
};

subtest 'lacnic_read_query: permission denied on %201' => sub {
    my $sock = fake_sock([
        "%201 access denied\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_read_query( $sock, '200.0.0.1' );

    is $q{permission}, 'denied', 'permission denied';
    ok tied(*$sock)->{closed}, 'socket closed';
};

subtest 'lacnic_read_query: rate limit returns denied' => sub {
    my $sock = fake_sock([
        "% Query rate limit exceeded. Blocked for 300 seconds.\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_read_query( $sock, '200.0.0.1' );

    is $q{permission}, 'denied', 'rate limit treated as denied';
};

subtest 'lacnic_read_query: not assigned to LACNIC returns denied' => sub {
    my $sock = fake_sock([
        "% Not assigned to LACNIC\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_read_query( $sock, '1.0.0.1' );

    is $q{permission}, 'denied', 'not assigned treated as denied';
};

subtest 'lacnic_read_query: non-lacnic resource returns empty' => sub {
    my $sock = fake_sock([
        "% RIPE resource:\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_read_query( $sock, '193.0.0.1' );

    is scalar keys %q, 0, 'non-lacnic resource returns empty';
    ok tied(*$sock)->{closed}, 'socket closed on non-lacnic resource';
};

subtest 'lacnic_read_query: brazil resource accepted' => sub {
    my $sock = fake_sock([
        "% brazil resource:\n",
        "inetnum:     200.0.0.0/24\n",
        "owner:       Test\n",
        "country:     BR\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_read_query( $sock, '200.0.0.1' );

    is $q{country}, 'BR', 'brazil resource accepted as valid';
};

subtest 'lacnic_read_query: keeps first country value' => sub {
    my $sock = fake_sock([
        "inetnum:     200.0.0.0/24\n",
        "country:     BR\n",
        "country:     AR\n",
    ]);

    my %q = Net::Whois::IANA::lacnic_read_query( $sock, '200.0.0.1' );

    is $q{country}, 'BR', 'first country kept';
};

# =============================================================================
# afrinic_read_query (alias for apnic_read_query)
# =============================================================================

subtest 'afrinic_read_query is apnic_read_query' => sub {
    is \&Net::Whois::IANA::afrinic_read_query,
       \&Net::Whois::IANA::apnic_read_query,
       'afrinic_read_query is aliased to apnic_read_query';
};

subtest 'afrinic_read_query: standard response' => sub {
    my $sock = fake_sock([
        "% Information related to '196.0.0.0 - 196.0.0.255'\n",
        "\n",
        "inetnum:        196.0.0.0 - 196.0.0.255\n",
        "netname:        AFRINIC-TEST\n",
        "descr:          Test African Network\n",
        "country:        ZA\n",
        "source:         AFRINIC\n",
    ]);

    my %q = Net::Whois::IANA::afrinic_read_query( $sock, '196.0.0.1' );

    is $q{inetnum}, '196.0.0.0 - 196.0.0.255', 'inetnum parsed';
    is $q{country}, 'ZA', 'country parsed';
    is $q{source},  'AFRINIC', 'source parsed';
};

# =============================================================================
# jpnic_read_query
# =============================================================================

subtest 'jpnic_read_query: bracket-style fields' => sub {
    my $sock = fake_sock([
        "[ JPNIC database provides information regarding IP address and ASN. ]\n",
        "\n",
        "a. [Network Number]     58.0.0.0/8\n",
        "b. [Network Name]       JPNIC-NET-JP\n",
        "g. [Organization Name]  Japan Network Information Center\n",
        "[Assigned Date]         2005/01/28\n",
        "country:        JP\n",
    ]);

    my %q = Net::Whois::IANA::jpnic_read_query( $sock, '58.0.0.1' );

    is $q{inetnum}, '58.0.0.0/8', 'network number mapped to inetnum';
    is $q{netname}, 'JPNIC-NET-JP', 'network name mapped to netname';
    is $q{descr}, 'Japan Network Information Center', 'organization name mapped to descr';
    is $q{'assigned date'}, '2005/01/28', 'bracket-only field parsed';
    is $q{country}, 'JP', 'country parsed from colon format';
    like $q{fullinfo}, qr/JPNIC database/, 'fullinfo contains raw output';
};

subtest 'jpnic_read_query: standard colon format' => sub {
    my $sock = fake_sock([
        "inetnum:        58.0.0.0 - 58.255.255.255\n",
        "netname:        JPNIC-NET\n",
        "country:        JP\n",
        "source:         JPNIC\n",
    ]);

    my %q = Net::Whois::IANA::jpnic_read_query( $sock, '58.0.0.1' );

    is $q{inetnum}, '58.0.0.0 - 58.255.255.255', 'inetnum from colon format';
    is $q{netname}, 'JPNIC-NET', 'netname from colon format';
};

subtest 'jpnic_read_query: permission denied' => sub {
    my $sock = fake_sock([
        "%201 access denied\n",
    ]);

    my %q = Net::Whois::IANA::jpnic_read_query( $sock, '58.0.0.1' );

    is $q{permission}, 'denied', 'permission denied on %201';
    ok tied(*$sock)->{closed}, 'socket closed';
};

subtest 'jpnic_read_query: skips comment lines' => sub {
    my $sock = fake_sock([
        "% query results\n",
        "# another comment\n",
        "netname:        TEST\n",
        "country:        JP\n",
    ]);

    my %q = Net::Whois::IANA::jpnic_read_query( $sock, '58.0.0.1' );

    is $q{netname}, 'TEST', 'data parsed after comments';
};

# =============================================================================
# krnic_read_query and idnic_read_query are aliases for apnic_read_query
# =============================================================================

subtest 'krnic_read_query is apnic_read_query' => sub {
    is \&Net::Whois::IANA::krnic_read_query,
       \&Net::Whois::IANA::apnic_read_query,
       'krnic_read_query aliased to apnic_read_query';
};

subtest 'idnic_read_query is apnic_read_query' => sub {
    is \&Net::Whois::IANA::idnic_read_query,
       \&Net::Whois::IANA::apnic_read_query,
       'idnic_read_query aliased to apnic_read_query';
};

# =============================================================================
# Edge cases: fullinfo accumulation
# =============================================================================

subtest 'fullinfo accumulates all raw lines including comments' => sub {
    my $sock = fake_sock([
        "% RIPE comment\n",
        "netname:        TEST\n",
        "non-colon line\n",
        "country:        US\n",
    ]);

    my %q = Net::Whois::IANA::ripe_read_query( $sock, '10.0.0.1' );

    like $q{fullinfo}, qr/RIPE comment/, 'comment in fullinfo';
    like $q{fullinfo}, qr/non-colon line/, 'non-colon line in fullinfo';
    like $q{fullinfo}, qr/netname.*TEST/, 'data lines in fullinfo';
};

subtest 'ripe_read_query: values with colons preserve data after first split' => sub {
    my $sock = fake_sock([
        "descr:          URL: http://example.com\n",
        "country:        UK\n",
    ]);

    my %q = Net::Whois::IANA::ripe_read_query( $sock, '10.0.0.1' );

    is $q{descr}, 'URL: http://example.com', 'colon in value preserved (split :, 2)';
};

done_testing;
