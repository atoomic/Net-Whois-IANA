#!/usr/bin/env perl

use strict;
use warnings;

# Override sleep before any modules are loaded so Perl compiles sleep calls
# against our override rather than the built-in.
our @SLEEP_LOG;
BEGIN { *CORE::GLOBAL::sleep = sub { push @SLEEP_LOG, $_[0] } }

use Test2::V0;
use Test2::Tools::Explain;

use Net::Whois::IANA;

use Test::MockModule;

# =============================================================================
# Unit tests for whois_connect().
# Fully mocked — no network required.
# =============================================================================

my $mock_io = Test::MockModule->new('IO::Socket::INET');

# --- argument handling ---

subtest 'accepts individual arguments (host, port, timeout)' => sub {
    my @captured;
    $mock_io->redefine(
        new => sub {
            my ( $class, %args ) = @_;
            @captured = @args{qw(PeerAddr PeerPort Timeout)};
            return bless {}, $class;
        },
    );

    my $sock = Net::Whois::IANA::whois_connect( 'whois.example.com', 43, 10 );
    ok( $sock, 'returns socket on success' );
    is( $captured[0], 'whois.example.com', 'host passed correctly' );
    is( $captured[1], 43,                  'port passed correctly' );
    is( $captured[2], 10,                  'timeout passed correctly' );
};

subtest 'accepts arrayref argument' => sub {
    my @captured;
    $mock_io->redefine(
        new => sub {
            my ( $class, %args ) = @_;
            @captured = @args{qw(PeerAddr PeerPort Timeout)};
            return bless {}, $class;
        },
    );

    my $sock = Net::Whois::IANA::whois_connect( [ 'whois.ripe.net', 4343, 5 ] );
    ok( $sock, 'returns socket from arrayref' );
    is( $captured[0], 'whois.ripe.net', 'host from arrayref' );
    is( $captured[1], 4343,             'port from arrayref' );
    is( $captured[2], 5,                'timeout from arrayref' );
};

subtest 'uses default port and timeout when not specified' => sub {
    my @captured;
    $mock_io->redefine(
        new => sub {
            my ( $class, %args ) = @_;
            @captured = @args{qw(PeerAddr PeerPort Timeout)};
            return bless {}, $class;
        },
    );

    my $sock = Net::Whois::IANA::whois_connect('whois.example.com');
    ok( $sock, 'returns socket with defaults' );
    is( $captured[1], $Net::Whois::IANA::WHOIS_PORT,    'default port used' );
    is( $captured[2], $Net::Whois::IANA::WHOIS_TIMEOUT, 'default timeout used' );
};

# --- success on first try ---

subtest 'returns socket immediately on first successful connect' => sub {
    my $call_count = 0;
    $mock_io->redefine(
        new => sub {
            $call_count++;
            return bless {}, $_[0];
        },
    );

    my $sock = Net::Whois::IANA::whois_connect( 'whois.example.com', 43, 1 );
    ok( $sock, 'socket returned' );
    is( $call_count, 1, 'IO::Socket::INET->new called exactly once' );
};

# --- retry on undef return (connection failure without exception) ---

subtest 'retries when IO::Socket::INET->new returns undef' => sub {
    my $call_count = 0;
    $mock_io->redefine(
        new => sub {
            $call_count++;
            return $call_count == 3 ? bless( {}, $_[0] ) : undef;
        },
    );

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };
    @SLEEP_LOG = ();

    my $sock = Net::Whois::IANA::whois_connect( 'fail.example.com', 43, 1 );
    ok( $sock,            'succeeds on third attempt' );
    is( $call_count, 3,   'tried 3 times (initial + 2 retries)' );
    ok( @warnings >= 2,   'warnings emitted for failed attempts' );
};

subtest 'returns 0 after all retries exhausted (undef returns)' => sub {
    my $call_count = 0;
    $mock_io->redefine(
        new => sub {
            $call_count++;
            return undef;
        },
    );

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };
    @SLEEP_LOG = ();

    my $result = Net::Whois::IANA::whois_connect( 'fail.example.com', 43, 1 );
    is( $result, 0,       'returns 0 after exhausting retries' );
    is( $call_count, 3,   'all 3 attempts were made' );
};

# --- retry on exception (die inside IO::Socket::INET->new) ---

subtest 'retries when IO::Socket::INET->new dies' => sub {
    my $call_count = 0;
    $mock_io->redefine(
        new => sub {
            $call_count++;
            die "Simulated socket error" if $call_count < 3;
            return bless {}, $_[0];
        },
    );

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };
    @SLEEP_LOG = ();

    my $sock = Net::Whois::IANA::whois_connect( 'die.example.com', 43, 1 );
    ok( $sock,          'succeeds after exceptions' );
    is( $call_count, 3, 'retried through die' );
};

subtest 'returns 0 after all retries exhausted (die)' => sub {
    my $call_count = 0;
    $mock_io->redefine(
        new => sub {
            $call_count++;
            die "Permanent failure";
        },
    );

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };
    @SLEEP_LOG = ();

    my $result = Net::Whois::IANA::whois_connect( 'die.example.com', 43, 1 );
    is( $result, 0,     'returns 0 after all die' );
    is( $call_count, 3, 'tried 3 times' );
};

# --- sleep behavior ---

subtest 'sleeps between retries but not after the last attempt' => sub {
    $mock_io->redefine( new => sub { undef } );

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, $_[0] };
    @SLEEP_LOG = ();

    Net::Whois::IANA::whois_connect( 'slow.example.com', 43, 1 );
    is( scalar @SLEEP_LOG, 2, 'sleep called twice (not after last attempt)' );
    is( $SLEEP_LOG[0], 2,     'sleep duration is 2 seconds' );
    is( $SLEEP_LOG[1], 2,     'second sleep also 2 seconds' );
};

done_testing;
