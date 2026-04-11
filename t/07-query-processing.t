#!/usr/bin/env perl

use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;

use Net::Whois::IANA;

# =============================================================================
# These tests cover the *_process_query functions which are pure hash→hash
# transformations — no network required.
# =============================================================================

# --- ripe_process_query ---

subtest 'ripe_process_query' => sub {

    subtest 'valid query with inetnum' => sub {
        my %result = Net::Whois::IANA::ripe_process_query(
            inetnum => '193.0.0.0 - 193.0.7.255',
            country => 'NL',
            netname => 'RIPE-NCC',
            descr   => 'RIPE Network Coordination Centre',
            source  => 'RIPE',
        );
        is $result{permission}, 'allowed', 'permission set';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
        ok scalar @{ $result{cidr} }, 'cidr has entries';
        is $result{country}, 'NL', 'country preserved';
    };

    subtest 'valid query with inet6num' => sub {
        my %result = Net::Whois::IANA::ripe_process_query(
            inet6num => '2001:0DB8::/32',
            country  => 'EU',
            netname  => 'TEST-NET',
        );
        is $result{permission}, 'allowed', 'permission set';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
    };

    subtest 'rejects IANA-BLK netname' => sub {
        my %result = Net::Whois::IANA::ripe_process_query(
            inetnum => '10.0.0.0 - 10.255.255.255',
            country => 'EU',
            netname => 'IANA-BLK',
        );
        is scalar keys %result, 0, 'returns empty for IANA-BLK';
    };

    subtest 'rejects worldwide country' => sub {
        my %result = Net::Whois::IANA::ripe_process_query(
            inetnum => '10.0.0.0 - 10.255.255.255',
            country => 'world wide',
            netname => 'SOME-NET',
        );
        is scalar keys %result, 0, 'returns empty for world wide country';
    };

    subtest 'rejects worldwide remarks' => sub {
        my %result = Net::Whois::IANA::ripe_process_query(
            inetnum => '10.0.0.0 - 10.255.255.255',
            remarks => 'The country is really world wide',
            netname => 'SOME-NET',
            country => 'EU',
        );
        is scalar keys %result, 0, 'returns empty for world wide remarks';
    };

    subtest 'rejects AFRINIC-NET-TRANSFERRED' => sub {
        my %result = Net::Whois::IANA::ripe_process_query(
            inetnum => '102.0.0.0 - 102.255.255.255',
            country => 'EU',
            netname => 'AFRINIC-NET-TRANSFERRED',
        );
        is scalar keys %result, 0, 'returns empty for transferred block';
    };

    subtest 'rejects missing inetnum and inet6num' => sub {
        my %result = Net::Whois::IANA::ripe_process_query(
            country => 'NL',
            netname => 'RIPE-NCC',
        );
        is scalar keys %result, 0, 'returns empty without inetnum';
    };
};

# --- apnic_process_query ---

subtest 'apnic_process_query' => sub {

    subtest 'valid query' => sub {
        my %result = Net::Whois::IANA::apnic_process_query(
            inetnum => '1.0.0.0 - 1.0.0.255',
            country => 'AU',
            netname => 'APNIC-LABS',
            descr   => 'APNIC Research and Development',
        );
        is $result{permission}, 'allowed', 'permission set';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
    };

    subtest 'rejects not-administered' => sub {
        my %result = Net::Whois::IANA::apnic_process_query(
            inetnum => '10.0.0.0 - 10.255.255.255',
            remarks => 'address range is not administered by APNIC',
            country => 'AU',
        );
        is scalar keys %result, 0, 'returns empty for non-APNIC range';
    };

    subtest 'rejects not-allocated descr' => sub {
        my %result = Net::Whois::IANA::apnic_process_query(
            inetnum => '10.0.0.0 - 10.255.255.255',
            descr   => 'not allocated to APNIC',
            country => 'AU',
        );
        is scalar keys %result, 0, 'returns empty for not allocated descr';
    };

    subtest 'rejects placeholder reference descr' => sub {
        my %result = Net::Whois::IANA::apnic_process_query(
            inetnum => '10.0.0.0 - 10.255.255.255',
            descr   => 'placeholder reference for route objects',
            country => 'AU',
        );
        is scalar keys %result, 0, 'returns empty for placeholder';
    };

    subtest 'rejects missing inetnum' => sub {
        my %result = Net::Whois::IANA::apnic_process_query(
            country => 'AU',
            netname => 'TEST',
        );
        is scalar keys %result, 0, 'returns empty without inetnum';
    };
};

# --- arin_process_query ---

subtest 'arin_process_query' => sub {

    subtest 'valid query' => sub {
        my %result = Net::Whois::IANA::arin_process_query(
            orgname  => 'Google LLC',
            orgid    => 'GOGL',
            netrange => '8.8.8.0 - 8.8.8.255',
            cidr     => '8.8.8.0/24',
            nettype  => 'Direct Allocation',
            comment  => 'Some comment',
        );
        is $result{permission}, 'allowed', 'permission set';
        is $result{descr}, 'Google LLC', 'descr mapped from orgname';
        is $result{status}, 'Direct Allocation', 'status mapped from nettype';
        is $result{inetnum}, '8.8.8.0 - 8.8.8.255', 'inetnum mapped from netrange';
        is $result{source}, 'ARIN', 'source set';
        is $result{remarks}, 'Some comment', 'remarks mapped from comment';
        is $result{cidr}, '8.8.8.0/24', 'cidr passed through as-is (post_process_query normalizes)';
    };

    subtest 'passes through comma-separated CIDR for post_process_query' => sub {
        my %result = Net::Whois::IANA::arin_process_query(
            orgname  => 'Test Org',
            orgid    => 'TEST',
            netrange => '10.0.0.0 - 10.1.255.255',
            cidr     => '10.0.0.0/16, 10.1.0.0/16',
            nettype  => 'Direct Allocation',
        );
        is $result{cidr}, '10.0.0.0/16, 10.1.0.0/16',
            'cidr string preserved (post_process_query splits it)';
    };

    subtest 'rejects RIPE orgid' => sub {
        my %result = Net::Whois::IANA::arin_process_query(
            orgname  => 'RIPE NCC',
            orgid    => 'RIPE',
            netrange => '193.0.0.0 - 193.0.7.255',
            cidr     => '193.0.0.0/21',
        );
        is scalar keys %result, 0, 'returns empty for RIPE orgid';
    };

    subtest 'rejects APNIC orgid' => sub {
        my %result = Net::Whois::IANA::arin_process_query(
            orgname  => 'APNIC',
            orgid    => 'APNIC',
            netrange => '1.0.0.0 - 1.0.0.255',
            cidr     => '1.0.0.0/24',
        );
        is scalar keys %result, 0, 'returns empty for APNIC orgid';
    };

    subtest 'rejects LACNIC orgid' => sub {
        my %result = Net::Whois::IANA::arin_process_query(
            orgname  => 'LACNIC',
            orgid    => 'LACNIC',
            netrange => '200.0.0.0 - 200.0.0.255',
            cidr     => '200.0.0.0/24',
        );
        is scalar keys %result, 0, 'returns empty for LACNIC orgid';
    };

    subtest 'rejects AFRINIC orgid' => sub {
        my %result = Net::Whois::IANA::arin_process_query(
            orgname  => 'AFRINIC',
            orgid    => 'AFRINIC',
            netrange => '102.0.0.0 - 102.0.0.255',
            cidr     => '102.0.0.0/24',
        );
        is scalar keys %result, 0, 'returns empty for AFRINIC orgid';
    };

    subtest 'does not reject orgid containing registry name as substring' => sub {
        my %result = Net::Whois::IANA::arin_process_query(
            orgname  => 'LACNIC-PARTNER Corp',
            orgid    => 'LACNIC-PARTNER',
            netrange => '10.0.0.0 - 10.0.0.255',
            cidr     => '10.0.0.0/24',
            nettype  => 'Direct Allocation',
        );
        ok scalar keys %result, 'orgid with registry substring is not rejected';
        is $result{permission}, 'allowed', 'permission set';
    };

    subtest 'rejects orgid with leading/trailing whitespace' => sub {
        my %result = Net::Whois::IANA::arin_process_query(
            orgname  => 'APNIC',
            orgid    => '  APNIC  ',
            netrange => '1.0.0.0 - 1.0.0.255',
            cidr     => '1.0.0.0/24',
        );
        is scalar keys %result, 0, 'whitespace-padded orgid still rejected';
    };
};

# --- lacnic_process_query ---

subtest 'lacnic_process_query' => sub {

    subtest 'valid query' => sub {
        my %result = Net::Whois::IANA::lacnic_process_query(
            owner   => 'Telefonica Brasil S.A',
            ownerid => 'TELEPHO',
            inetnum => '200.0.0.0/16',
            country => 'BR',
        );
        is $result{permission}, 'allowed', 'permission set';
        is $result{descr}, 'Telefonica Brasil S.A', 'descr mapped from owner';
        is $result{netname}, 'TELEPHO', 'netname mapped from ownerid';
        is $result{source}, 'LACNIC', 'source set';
        is $result{country}, 'BR', 'country preserved';
        is $result{cidr}, '200.0.0.0/16', 'cidr preserved from inetnum';
        like $result{inetnum}, qr/200\.0\.0\.0\s*-\s*200\.0\.255\.255/, 'inetnum converted from CIDR to range';
    };

    subtest 'handles missing inetnum' => sub {
        my %result = Net::Whois::IANA::lacnic_process_query(
            owner   => 'Some Org',
            ownerid => 'SOMEORG',
            country => 'BR',
        );
        is $result{permission}, 'allowed', 'permission set even without inetnum';
        ok !exists $result{cidr}, 'cidr not set without inetnum';
    };

    subtest 'country fallback from nserver' => sub {
        my %result = Net::Whois::IANA::lacnic_process_query(
            owner   => 'Some Org',
            ownerid => 'SOMEORG',
            inetnum => '200.0.0.0/16',
            nserver => 'ns1.example.br',
        );
        is $result{country}, 'BR', 'country extracted from nserver TLD';
    };

    subtest 'country fallback from descr' => sub {
        my %result = Net::Whois::IANA::lacnic_process_query(
            owner   => 'Some Org AR',
            ownerid => 'SOMEORG',
            inetnum => '200.0.0.0/16',
        );
        is $result{country}, 'AR', 'country extracted from descr suffix';
    };

    subtest 'rejects missing country with no fallback' => sub {
        my %result = Net::Whois::IANA::lacnic_process_query(
            owner   => 'SomeOrg',
            ownerid => 'SOMEORG',
            inetnum => '200.0.0.0/16',
        );
        is scalar keys %result, 0, 'returns empty when no country found';
    };

    subtest 'rejects missing inetnum and inet6num' => sub {
        my %result = Net::Whois::IANA::lacnic_process_query(
            owner   => 'Some Org',
            ownerid => 'SOMEORG',
            country => 'BR',
        );
        is scalar keys %result, 0, 'returns empty when no address range';
    };

    subtest 'inet6num produces CIDR' => sub {
        my %result = Net::Whois::IANA::lacnic_process_query(
            owner    => 'NIC.br',
            ownerid  => 'NICBR',
            inet6num => '2001:0db8:0000:0000:0000:0000:0000:0000 - 2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff',
            country  => 'BR',
        );
        is $result{permission}, 'allowed', 'permission set';
        is $result{source}, 'LACNIC', 'source set';
        ok ref $result{cidr} eq 'ARRAY', 'cidr is arrayref';
        ok scalar @{ $result{cidr} } > 0, 'cidr is non-empty';
        like $result{cidr}[0], qr/2001:/, 'cidr contains IPv6 prefix';
    };
};

# --- afrinic_process_query ---

subtest 'afrinic_process_query' => sub {

    subtest 'valid query' => sub {
        my %result = Net::Whois::IANA::afrinic_process_query(
            inetnum => '102.0.0.0 - 102.255.255.255',
            country => 'ZA',
            netname => 'AFRINIC-NET',
            descr   => 'AFRINIC',
        );
        is $result{permission}, 'allowed', 'permission set';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
    };

    subtest 'rejects worldwide remarks' => sub {
        my %result = Net::Whois::IANA::afrinic_process_query(
            inetnum => '102.0.0.0 - 102.255.255.255',
            remarks => 'country is really worldwide',
            country => 'ZA',
        );
        is scalar keys %result, 0, 'returns empty for worldwide';
    };

    subtest 'rejects in-addr.arpa descr' => sub {
        my %result = Net::Whois::IANA::afrinic_process_query(
            inetnum => '102.0.0.0 - 102.255.255.255',
            descr   => 'Here for in-addr.arpa authentication',
            country => 'ZA',
        );
        is scalar keys %result, 0, 'returns empty for in-addr.arpa';
    };

    subtest 'rejects missing inetnum' => sub {
        my %result = Net::Whois::IANA::afrinic_process_query(
            country => 'ZA',
            netname => 'TEST',
        );
        is scalar keys %result, 0, 'returns empty without inetnum';
    };
};

# --- jpnic_process_query ---

subtest 'jpnic_process_query' => sub {

    subtest 'valid query with inetnum in CIDR notation' => sub {
        my %result = Net::Whois::IANA::jpnic_process_query(
            inetnum => '58.0.0.0/8',
            country => 'JP',
            netname => 'JPNIC-NET',
            descr   => 'Japan Network Information Center',
        );
        is $result{permission}, 'allowed', 'permission set';
        is $result{source}, 'JPNIC', 'source set to JPNIC';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
        is $result{cidr}[0], '58.0.0.0/8', 'cidr preserved from CIDR notation';
    };

    subtest 'valid query with range inetnum' => sub {
        my %result = Net::Whois::IANA::jpnic_process_query(
            inetnum => '58.0.0.0 - 58.255.255.255',
            country => 'JP',
            netname => 'JPNIC-NET',
        );
        is $result{permission}, 'allowed', 'permission set';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
        ok scalar @{ $result{cidr} }, 'cidr has entries';
    };

    subtest 'valid query with inet6num' => sub {
        my %result = Net::Whois::IANA::jpnic_process_query(
            inet6num => '2001:0DB8::/32',
            country  => 'JP',
        );
        is $result{permission}, 'allowed', 'permission set';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
    };

    subtest 'rejects missing inetnum and inet6num' => sub {
        my %result = Net::Whois::IANA::jpnic_process_query(
            country => 'JP',
            netname => 'JPNIC-NET',
        );
        is scalar keys %result, 0, 'returns empty without inetnum';
    };
};

# --- krnic_process_query ---

subtest 'krnic_process_query' => sub {

    subtest 'valid query with inetnum' => sub {
        my %result = Net::Whois::IANA::krnic_process_query(
            inetnum => '59.0.0.0 - 59.25.255.255',
            country => 'KR',
            netname => 'KRNIC-NET',
            descr   => 'Korea Internet & Security Agency',
        );
        is $result{permission}, 'allowed', 'permission set';
        is $result{source}, 'KRNIC', 'source set to KRNIC';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
    };

    subtest 'valid query with ipv4 address field' => sub {
        my %result = Net::Whois::IANA::krnic_process_query(
            'ipv4 address' => '59.0.0.0 - 59.25.255.255',
            country        => 'KR',
            netname        => 'KRNIC-NET',
        );
        is $result{permission}, 'allowed', 'permission set';
        is $result{inetnum}, '59.0.0.0 - 59.25.255.255', 'inetnum mapped from ipv4 address';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
    };

    subtest 'rejects missing inetnum and ipv4 address' => sub {
        my %result = Net::Whois::IANA::krnic_process_query(
            country => 'KR',
            netname => 'TEST',
        );
        is scalar keys %result, 0, 'returns empty without address info';
    };
};

# --- idnic_process_query ---

subtest 'idnic_process_query' => sub {

    subtest 'valid query' => sub {
        my %result = Net::Whois::IANA::idnic_process_query(
            inetnum => '49.0.0.0 - 49.255.255.255',
            country => 'ID',
            netname => 'IDNIC-NET',
            descr   => 'Indonesia Network Information Center',
        );
        is $result{permission}, 'allowed', 'permission set';
        is $result{source}, 'IDNIC', 'source set to IDNIC';
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
    };

    subtest 'rejects missing inetnum' => sub {
        my %result = Net::Whois::IANA::idnic_process_query(
            country => 'ID',
            netname => 'TEST',
        );
        is scalar keys %result, 0, 'returns empty without inetnum';
    };
};

# --- post_process_query ---

subtest 'post_process_query' => sub {

    subtest 'extracts abuse from abuse-keyed field' => sub {
        my %result = Net::Whois::IANA::post_process_query(
            'abuse-mailbox' => 'abuse@example.com',
            country         => 'US',
            cidr            => '10.0.0.0/8',
            fullinfo        => '',
        );
        is $result{abuse}, 'abuse@example.com', 'abuse extracted from abuse-* field';
    };

    subtest 'extracts abuse from fullinfo' => sub {
        my %result = Net::Whois::IANA::post_process_query(
            country  => 'US',
            cidr     => '10.0.0.0/8',
            fullinfo => "some text\nabuse\@example.net more text",
        );
        is $result{abuse}, 'abuse@example.net', 'abuse from fullinfo';
    };

    subtest 'falls back to email field' => sub {
        my %result = Net::Whois::IANA::post_process_query(
            country  => 'US',
            cidr     => '10.0.0.0/8',
            email    => 'contact@example.com',
            fullinfo => '',
        );
        is $result{abuse}, 'contact@example.com', 'abuse falls back to email';
    };

    subtest 'falls back to e-mail field' => sub {
        my %result = Net::Whois::IANA::post_process_query(
            country    => 'US',
            cidr       => '10.0.0.0/8',
            'e-mail'   => 'tech@example.com',
            fullinfo   => '',
        );
        is $result{abuse}, 'tech@example.com', 'abuse falls back to e-mail';
    };

    subtest 'normalizes comma-separated cidr to array' => sub {
        my %result = Net::Whois::IANA::post_process_query(
            cidr     => '10.0.0.0/16, 10.1.0.0/16',
            fullinfo => '',
        );
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
        is scalar @{ $result{cidr} }, 2, 'two entries';
    };

    subtest 'wraps single cidr in array' => sub {
        my %result = Net::Whois::IANA::post_process_query(
            cidr     => '10.0.0.0/8',
            fullinfo => '',
        );
        is ref $result{cidr}, 'ARRAY', 'cidr is arrayref';
        is $result{cidr}[0], '10.0.0.0/8', 'value preserved';
    };

    subtest 'preserves arrayref cidr' => sub {
        my %result = Net::Whois::IANA::post_process_query(
            cidr     => ['10.0.0.0/8'],
            fullinfo => '',
        );
        is ref $result{cidr}, 'ARRAY', 'cidr stays arrayref';
    };
};

done_testing;
