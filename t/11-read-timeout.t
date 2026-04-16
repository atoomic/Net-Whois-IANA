#!/usr/bin/env perl

use strict;
use warnings;

use Test2::V0;

use Net::Whois::IANA;

# =============================================================================
# Unit tests for the read-timeout helper.
#
# IO::Socket::INET's Timeout parameter only governs connect; once the socket
# is up, `while (<$sock>)` blocks forever on a stalled server. This test
# uses socketpair() to create a half of a connected pair where nothing is
# ever written, and verifies that:
#
#   1. _readline_with_timeout returns undef within the timeout window
#   2. a warning is emitted so the failure is not silent
#   3. the stash on `${ *$sock }{_net_whois_iana_timeout}` is honored
# =============================================================================

use Socket ();

my ($read_sock, $write_sock);
my $ok = eval {
    socketpair( $read_sock, $write_sock, Socket::AF_UNIX(), Socket::SOCK_STREAM(), Socket::PF_UNSPEC() );
};

if ( !$ok || !defined $read_sock ) {
    plan skip_all => "socketpair not supported on this platform: $@";
}

# Stash a 1-second timeout the way whois_connect does.
${ *$read_sock }{_net_whois_iana_timeout} = 1;

subtest 'read times out and emits a warning when no data arrives' => sub {
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };

    my $start = time();
    my $line  = Net::Whois::IANA::_readline_with_timeout($read_sock);
    my $elapsed = time() - $start;

    is $line, undef, 'returns undef when the read deadline expires';
    ok $elapsed < 3, "did not block past the deadline (took ${elapsed}s)";
    ok scalar( grep { /timed out/i } @warnings ), 'warning mentions the timeout'
        or diag "warnings were: @warnings";
};

subtest 'read returns the next line when data is available' => sub {
    syswrite( $write_sock, "hello\nworld\n" );

    my $first = Net::Whois::IANA::_readline_with_timeout($read_sock);
    is $first, "hello\n", 'first line is read';

    my $second = Net::Whois::IANA::_readline_with_timeout($read_sock);
    is $second, "world\n", 'second line is read';
};

subtest 'falls back gracefully on tied filehandles (no fileno)' => sub {
    {
        package TimeoutFakeHandle;
        use Tie::Handle;
        use base 'Tie::Handle';
        sub TIEHANDLE { my ($class, $lines) = @_; bless { lines => [@{$lines||[]}] }, $class }
        sub PRINT    { 1 }
        sub READLINE { shift @{ $_[0]->{lines} } }
        sub CLOSE    { 1 }
    }

    no strict 'refs';
    my $name = 'TimeoutFakeHandle::SOCK_one';
    tie *{$name}, 'TimeoutFakeHandle', [ "line-a\n", "line-b\n" ];
    my $sock = \*{$name};

    is Net::Whois::IANA::_readline_with_timeout($sock), "line-a\n",
       'tied handle falls back to plain readline (first line)';
    is Net::Whois::IANA::_readline_with_timeout($sock), "line-b\n",
       'tied handle falls back to plain readline (second line)';
    is Net::Whois::IANA::_readline_with_timeout($sock), undef,
       'tied handle EOF returns undef';
};

subtest 'whois_connect stashes timeout on returned socket' => sub {
    # Spin up a localhost listener so whois_connect actually returns a socket.
    require IO::Socket::INET;
    my $server = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Proto     => 'tcp',
        Listen    => 1,
        ReuseAddr => 1,
    ) or do {
        plan skip_all => "cannot bind localhost listener: $!";
    };

    my $port = $server->sockport;
    my $sock = Net::Whois::IANA::whois_connect( '127.0.0.1', $port, 7 );
    ok $sock, 'connect succeeds';
    is ${ *$sock }{_net_whois_iana_timeout}, 7,
       'timeout from whois_connect is stashed on the socket';

    close $sock;
    close $server;
};

done_testing;
