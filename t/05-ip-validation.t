#!/usr/bin/env perl

use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;

use Net::Whois::IANA;

# --- is_valid_ipv4 ---

my @valid_ipv4 = (
    '0.0.0.0',
    '1.2.3.4',
    '127.0.0.1',
    '192.168.1.1',
    '255.255.255.255',
    '10.0.0.0',
    '172.16.0.1',
);

my @invalid_ipv4 = (
    '256.1.1.1',       # octet > 255
    '1.2.3.256',       # last octet > 255
    '1.2.3',           # too few octets
    '1.2.3.4.5',       # too many octets
    'a.b.c.d',         # non-numeric
    '',                 # empty
    '1.2.3.4a',        # trailing alpha
    '1.2.3.-1',        # negative
    '01onal.2.3.4',    # non-digit chars
);

for my $ip (@valid_ipv4) {
    ok( Net::Whois::IANA::is_valid_ipv4($ip), "ipv4 valid: $ip" );
}

for my $ip (@invalid_ipv4) {
    ok( !Net::Whois::IANA::is_valid_ipv4($ip), "ipv4 invalid: '$ip'" );
}

# --- is_valid_ipv6 ---

my @valid_ipv6 = (
    '::1',                              # loopback
    '::',                               # all zeros (compressed)
    'fe80::1',                          # link-local
    '2001:0db8:85a3:0000:0000:8a2e:0370:7334',  # full form
    '2001:db8:85a3::8a2e:370:7334',     # compressed
    '::ffff:192.168.1.1',               # IPv4-mapped
    'fe80::1:2:3:4',                    # partial compression
    '2001:db8::1',                      # simple compressed
    '1:2:3:4:5:6:7:8',                  # full no compression
);

my @invalid_ipv6 = (
    ':1',                               # single leading colon
    '1:',                               # single trailing colon
    '1::2::3',                          # double compression
    '12345::1',                         # segment > 4 hex chars
    '1:2:3:4:5:6:7:8:9',               # too many segments
    'gggg::1',                          # invalid hex
    '',                                 # empty
);

for my $ip (@valid_ipv6) {
    ok( Net::Whois::IANA::is_valid_ipv6($ip), "ipv6 valid: $ip" );
}

for my $ip (@invalid_ipv6) {
    ok( !Net::Whois::IANA::is_valid_ipv6($ip), "ipv6 invalid: '$ip'" );
}

# --- is_valid_ip (dispatch) ---

ok( Net::Whois::IANA::is_valid_ip('192.168.1.1'),  'is_valid_ip dispatches ipv4' );
ok( Net::Whois::IANA::is_valid_ip('::1'),           'is_valid_ip dispatches ipv6' );
ok( !Net::Whois::IANA::is_valid_ip(undef),          'is_valid_ip rejects undef' );
ok( !Net::Whois::IANA::is_valid_ip(''),             'is_valid_ip rejects empty' );
ok( !Net::Whois::IANA::is_valid_ip('not-an-ip'),    'is_valid_ip rejects garbage' );

done_testing;
