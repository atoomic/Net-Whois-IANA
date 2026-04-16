package Net::Whois::IANA;

use 5.006;

use strict;
use warnings;

use Carp       ();
use IO::Select ();
use IO::Socket ();
use Net::CIDR  ();

use base 'Exporter';

# ABSTRACT: Net::Whois::IANA - A universal WHOIS data extractor.

our $WHOIS_PORT           = 43;
our $WHOIS_TIMEOUT        = 30;
our @DEFAULT_SOURCE_ORDER = qw(arin ripe apnic lacnic afrinic jpnic krnic idnic);

our %IANA;
our @IANA;

BEGIN {
    # populate the hash at compile time

    %IANA = (
        apnic   => [ [ 'whois.apnic.net', $WHOIS_PORT, $WHOIS_TIMEOUT, \&apnic_query ], ],
        ripe    => [ [ 'whois.ripe.net', $WHOIS_PORT, $WHOIS_TIMEOUT, \&ripe_query ], ],
        arin    => [ [ 'whois.arin.net', $WHOIS_PORT, $WHOIS_TIMEOUT, \&arin_query ], ],
        lacnic  => [ [ 'whois.lacnic.net', $WHOIS_PORT, $WHOIS_TIMEOUT, \&lacnic_query ], ],
        afrinic => [ [ 'whois.afrinic.net', $WHOIS_PORT, $WHOIS_TIMEOUT, \&afrinic_query ],
        ],
        jpnic => [ [ 'whois.nic.ad.jp', $WHOIS_PORT, $WHOIS_TIMEOUT, \&jpnic_query ], ],
        krnic => [ [ 'whois.kisa.or.kr', $WHOIS_PORT, $WHOIS_TIMEOUT, \&krnic_query ], ],
        idnic => [ [ 'whois.idnic.net', $WHOIS_PORT, $WHOIS_TIMEOUT, \&idnic_query ], ],
    );

    @IANA = sort keys %IANA;

    # accessors
    # do not use AUTOLOAD - only accept lowercase function name
    # define accessors at compile time
    my @accessors = qw{country netname descr status source server inetnum inet6num cidr abuse fullinfo};

    foreach my $accessor (@accessors) {
        no strict 'refs';
        *$accessor = sub {
            my ($self) = @_;
            die qq[$accessor is a method call] unless ref $self;
            return unless $self->{QUERY};
            return $self->{QUERY}->{$accessor};
        };
    }

    *desc = \&descr; # backward compatibility
}

our @EXPORT = qw( @IANA %IANA );

sub new ($) {

    my $proto = shift;
    my $class = ref $proto || $proto;
    my $self  = {};

    bless $self, $class;

    return $self;
}

sub whois_connect ($;$$) {
    my ( $host, $port, $timeout ) = @_;

    ( $host, $port, $timeout ) = @$host if ref $host;

    $port    ||= $WHOIS_PORT;
    $timeout ||= $WHOIS_TIMEOUT;

    #my $port    = $host_ref->[1] || $WHOIS_PORT;
    #my $timeout = $host_ref->[2] || $WHOIS_TIMEOUT;
    #my $host    = $host_ref->[0];
    my $retries = 2;
    my $sleep   = 2;

    my $sock;

    foreach my $iter ( 0 .. $retries ) {
        local $@;

        eval {
            $sock = IO::Socket::INET->new(
                PeerAddr => $host,
                PeerPort => $port,
                Timeout  => $timeout,
            );
        };

        if ($sock) {
            # Stash the timeout for the read phase. IO::Socket::INET's
            # Timeout parameter only governs connect; without this,
            # while (<$sock>) blocks indefinitely on a stalled server.
            ${ *$sock }{_net_whois_iana_timeout} = $timeout;
            return $sock;
        }

        Carp::carp "Cannot connect to $host at port $port";
        Carp::carp $@ if $@;
        sleep $sleep unless $iter == $retries;    # avoid the last sleep
    }
    return 0;
}

# _readline_with_timeout — drop-in replacement for `<$sock>` that enforces
# a read deadline. Falls back to plain readline when the handle has no
# fileno (tied/overloaded mocks used in tests).
#
# Uses sysread + a per-socket line buffer so that IO::Select->can_read,
# which reflects kernel-level readiness, isn't fooled by data sitting in
# PerlIO's stdio buffer (the classic select-on-buffered-IO trap).
#
# Returns one line (with trailing "\n") on success, the trailing partial
# line on EOF, and undef on timeout or sysread error.
sub _readline_with_timeout ($) {
    my ($sock) = @_;

    # Mock-friendly path: no fileno → no select possible. Tied filehandles
    # without FILENO return undef from fileno(); overloaded blessed objects
    # raise an error which we trap.
    my $fd = eval { fileno($sock) };
    if ( !defined $fd ) {
        return scalar <$sock>;
    }

    my $timeout = ${ *$sock }{_net_whois_iana_timeout};
    $timeout = $WHOIS_TIMEOUT unless defined $timeout;

    my $buf_ref = \${ *$sock }{_net_whois_iana_rdbuf};
    $$buf_ref = '' unless defined $$buf_ref;

    while (1) {

        # If a complete line is already buffered, return it without
        # touching the kernel.
        if ( $$buf_ref =~ s/\A([^\n]*\n)// ) {
            return $1;
        }

        my $select = IO::Select->new($sock);
        if ( !$select->can_read($timeout) ) {
            Carp::carp "whois read timed out after ${timeout}s";
            return undef;
        }

        my $chunk;
        my $n = sysread( $sock, $chunk, 4096 );
        if ( !defined $n ) {
            Carp::carp "whois read error: $!";
            return undef;
        }
        if ( $n == 0 ) {

            # EOF: flush any trailing partial line, then signal end.
            if ( length $$buf_ref ) {
                my $tail = $$buf_ref;
                $$buf_ref = '';
                return $tail;
            }
            return undef;
        }
        $$buf_ref .= $chunk;
    }
}

sub is_valid_ipv4 ($) {

    my $ip = shift;

    return $ip
      && $ip =~ /^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$/

      # not absolutely correct
      && ( ( $1 + 0 ) | ( $2 + 0 ) | ( $3 + 0 ) | ( $4 + 0 ) ) < 0x100;
}

sub is_valid_ipv6 {
    my ($ip) = @_;

    return unless defined $ip && length $ip;

    return
      if $ip =~ /^:[^:]/
      || $ip =~ /[^:]:$/;    # Can't have single : on front or back

    my @seg = split /:/, $ip, -1;    # -1 to keep trailing empty fields
                                     # Clean up leading/trailing double colon effects.
    shift @seg if $seg[0] eq '';
    pop @seg   if $seg[-1] eq '';

    my $max = 8;
    if ( $seg[-1] =~ tr/.// ) {
        return unless is_valid_ipv4( pop @seg );
        $max -= 2;
    }

    my $cmp;
    for my $seg (@seg) {
        if ( $seg eq '' ) {

            # Only one compression segment allowed.
            return if $cmp;
            ++$cmp;
            next;
        }
        return if $seg =~ /[^0-9a-fA-F]/;
        return if length $seg > 4;
    }
    if ($cmp) {

        # If compressed, we need fewer than $max segments, but at least 1
        return ( @seg && @seg < $max ) && 1;    # true returned as 1
    }

    # Not compressed, all segments need to be there.
    return $max == @seg;
}

# Is valid IP v4 or IP v6 address.
sub is_valid_ip ($) {
    my ($ip) = @_;

    return unless defined $ip;                  # shortcut earlier
    return index( $ip, ':' ) >= 0 ? is_valid_ipv6($ip) : is_valid_ipv4($ip);
}

sub set_source ($$) {

    my $self   = shift;
    my $source = shift;

    $self->{source} = {%IANA} || return 0 unless $source;
    return 0 unless $source;
    unless ( ref $source ) {
        if ( $IANA{$source} ) {
            $self->{source} = { $source => $IANA{$source} };
            return 0;
        }
        return 1;
    }
    return 2
      unless ref $source eq 'HASH'
      && ( scalar grep { ref $_ && ref $_ eq 'ARRAY' && @{$_} && ref $_->[0] && ref $_->[0] eq 'ARRAY' && @{ $_->[0] } && $_->[0][0] && ( !defined $_->[0][3] || ref $_->[0][3] eq 'CODE' ) } values %{$source} ) == scalar keys %{$source};
    $self->{source} = $source;
    return 0;
}

sub init_query ($%) {

    my $self  = shift;
    my %param = @_;

    if ( !is_valid_ip( $param{-ip} ) ) {
        warn q{
Method usage:
$iana->whois_query(
	-ip=>$ip,
	-debug=>$debug, # optional
	-whois=>$whois | -mywhois=>\%mywhois, # optional
};
        return {};
    }

    my $set_source = $self->set_source( $param{-whois} || $param{-mywhois} );
    if ( $set_source == 1 ) {
        warn "Unknown whois server requested. Known servers are:\n";
        warn join( ", ", @IANA ) . "\n";
        return {};
    }
    elsif ( $set_source == 2 ) {
        warn q{
Custom sources must be of form:
%source = (
	source_name1 => [
		[ source_host, source_port || undef, source_timeout || undef, \&source_query || undef ],
	],
	source_name1 => [
		[ source_host, source_port || undef, source_timeout || undef, \&source_query || undef ],
	],
	...,
);
		};
        return {};
    }
}

sub source_connect ($$) {
    my ( $self, $source_name ) = @_;

    foreach my $server_ref ( @{ $self->{source}{$source_name} } ) {
        if ( my $sock = whois_connect($server_ref) ) {
            my ( $whois_host, $whois_port, $whois_timeout, $query_code ) = @{$server_ref};
            $self->{query_sub} = $query_code
              && ref $query_code eq 'CODE' ? $query_code : \&default_query;
            $self->{whois_host} = $whois_host;
            return $sock;
        }
    }
    return undef;
}

sub post_process_query (%) {

    my %query = @_;
    for my $qkey ( keys %query ) {
        chomp $query{$qkey} if defined $query{$qkey};
        $query{abuse} = $query{$qkey} and last
          if $qkey =~ /abuse/i && $query{$qkey} =~ /\@/;
    }
    unless ( $query{abuse} ) {
        if ( $query{fullinfo} && $query{fullinfo} =~ /(\S*abuse\S*\@\S+)/m ) {
            $query{abuse} = $1;
        }
        elsif ( $query{email} || $query{'e-mail'} || $query{orgtechemail} ) {
            $query{abuse} =
              $query{email} || $query{'e-mail'} || $query{orgtechemail};
        }
    }
    if ( !ref $query{cidr} ) {
        if ( defined $query{cidr} && $query{cidr} =~ /\,/ ) {
            $query{cidr} = [ split( /\s*\,\s*/, $query{cidr} ) ];
        }
        else {
            $query{cidr} = [ $query{cidr} ];
        }
    }

    return %query;
}

sub whois_query ($%) {
    my ( $self, %params ) = @_;

    if ( my $err = $self->init_query(%params) ) {
        $self->{QUERY} = {};
        return $err;
    }
    $self->{QUERY} = {};

    # Iterate configured sources only: DEFAULT_SOURCE_ORDER for known sources,
    # then any custom source names not in the default list.
    my @sources = grep { exists $self->{source}{$_} } @DEFAULT_SOURCE_ORDER;
    {
        my %seen = map { $_ => 1 } @sources;
        push @sources, grep { !$seen{$_} } sort keys %{ $self->{source} };
    }

    for my $source_name (@sources) {
        print STDERR "Querying $source_name ...\n" if $params{-debug};
        my $sock = $self->source_connect($source_name)
          || Carp::carp "Connection failed to $source_name." && next;
        my %query = $self->{query_sub}( $sock, $params{-ip} );

        next unless keys %query;
        do { Carp::carp "Warning: permission denied at $source_name server $self->{whois_host}\n"; next }
          if $query{permission} && $query{permission} eq 'denied';
        $query{server} = uc $source_name;
        $self->{QUERY} = { post_process_query(%query) };

        return $self->{QUERY};
    }

    return {};
}

sub default_query ($$) {

    # NOTE: This fallback sends ARIN protocol ("+ $ip") regardless of the
    # target server.  Custom -mywhois sources that omit a code ref at
    # position 3 will silently use this ARIN-formatted query.
    return arin_query(@_);
}

sub ripe_read_query ($$) {

    my ( $sock, $ip ) = @_;

    my %query = ( fullinfo => '' );
    print $sock "-r $ip\n" or Carp::carp "write failed: $!";
    while ( defined( my $line = _readline_with_timeout($sock) ) ) {
        local $_ = $line;
        $query{fullinfo} .= $_;
        close $sock and return ( permission => 'denied' ) if /ERROR:201/;
        next if ( /^(\%|\#)/ || !/\:/ );
        s/\s+$//;
        my ( $field, $value ) = split( /:/, $_, 2 );
        $value =~ s/^\s+//;
        $query{ lc($field) } .= ( $query{ lc($field) } ? ' ' : '' ) . $value;
    }
    close $sock;
    return %query;
}

sub ripe_process_query (%) {

    my %query = @_;

    if (
        ( defined $query{remarks} && $query{remarks} =~ /The country is really world wide/ )
        || ( defined $query{netname}
            && $query{netname} =~ /IANA-BLK/ )
        || ( defined $query{netname}
            && $query{netname} =~ /AFRINIC-NET-TRANSFERRED/ )
        || ( defined $query{country}
            && $query{country} =~ /world wide/ )
    ) {
        return ();
    }
    elsif ( !$query{inet6num} && !$query{inetnum} ) {
        return ();
    }
    else {
        $query{permission} = 'allowed';
        $query{cidr} = [ Net::CIDR::range2cidr( uc( $query{inet6num} || $query{inetnum} ) ) ];
    }
    return %query;
}

sub ripe_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = ripe_read_query( $sock, $ip );
    return () unless defined $query{country};
    return ripe_process_query(%query);
}

sub apnic_read_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = ( fullinfo => '' );
    my %tmp;
    print $sock "-r $ip\n" or Carp::carp "write failed: $!";
    my $skip_block = 0;
    while ( defined( my $line = _readline_with_timeout($sock) ) ) {
        local $_ = $line;
        $query{fullinfo} .= $_;
        close $sock and return ( permission => 'denied' ) if /^\%201/;
        if (m{^\%}) {

            # Always skip 0.0.0.0 data
            # It looks like:
            # % Information related to '0.0.0.0 - 255.255.255.255'
            if (m{^\%.*0\.0\.0\.0\s+}) {
                $skip_block = 1;
                next;
            }
            $skip_block = 0;
            next;
        }
        next if $skip_block;
        next if ( !/\:/ );
        s/\s+$//;
        my ( $field, $value ) = split( /:/, $_, 2 );
        $value =~ s/^\s+//;
        if ( $field =~ /^inet6?num$/ ) {
            next if $value =~ m{0\.0\.0\.0\s+};
            %tmp             = %query;
            %query           = ();
            $query{fullinfo} = $tmp{fullinfo};
        }
        my $lc_field = lc($field);
        next if $lc_field eq 'country' && defined $query{$lc_field};
        $query{$lc_field} .= ( $query{$lc_field} ? ' ' : '' ) . $value;
    }
    close $sock;
    for ( keys %tmp ) {
        $query{$_} = $tmp{$_} if !defined $query{$_};
    }
    return %query;
}

sub apnic_process_query (%) {
    my %query = @_;

    if (
        ( defined $query{remarks} && $query{remarks} =~ /address range is not administered by APNIC|This network in not allocated/ )
        || ( defined $query{descr}
            && $query{descr} =~ /not allocated to|by APNIC|placeholder reference/i )
    ) {
        return ();
    }
    elsif ( !$query{inet6num} && !$query{inetnum} ) {
        return ();
    }
    else {
        $query{permission} = 'allowed';
        $query{cidr} = [ Net::CIDR::range2cidr( uc( $query{inet6num} || $query{inetnum} ) ) ];
    }

    return %query;
}

sub apnic_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = apnic_read_query( $sock, $ip );
    return apnic_process_query(%query);
}

sub arin_read_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = ( fullinfo => '' );
    my %tmp = ();

    print $sock "+ $ip\n" or Carp::carp "write failed: $!";
    while ( defined( my $line = _readline_with_timeout($sock) ) ) {
        local $_ = $line;
        $query{fullinfo} .= $_;
        close $sock and return ( permission => 'denied' ) if /^\#201/;
        return () if /no match found for/i;
        next if ( /^\#/ || !/\:/ );
        s/\s+$//;
        my ( $field, $value ) = split( /:/, $_, 2 );
        $value =~ s/^\s+//;
        if (   $field eq 'OrgName'
            || $field eq 'CustName' ) {
            %tmp             = %query;
            %query           = ();
            $query{fullinfo} = $tmp{fullinfo};
        }
        $query{ lc($field) } .= ( $query{ lc($field) } ? ' ' : '' ) . $value;
    }
    close $sock;

    $query{orgname} = $query{custname} if defined $query{custname};

    for ( keys %tmp ) {
        $query{$_} = $tmp{$_} unless defined $query{$_};
    }

    return %query;
}

sub arin_process_query (%) {
    my %query = @_;

    return ()
      if $query{orgid} && $query{orgid} =~ /^\s*(?:RIPE|LACNIC|APNIC|AFRINIC)\s*$/;

    $query{permission} = 'allowed';
    $query{descr}      = $query{orgname};
    $query{remarks}    = $query{comment};
    $query{status}     = $query{nettype};
    $query{inetnum}    = $query{netrange};
    $query{source}     = 'ARIN';
    if ( defined $query{cidr} && $query{cidr} =~ /\,/ ) {
        $query{cidr} = [ split( /\s*\,\s*/, $query{cidr} ) ];
    }
    else {
        $query{cidr} = [ $query{cidr} ];
    }

    return %query;
}

sub arin_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = arin_read_query( $sock, $ip );

    return arin_process_query(%query);
}

sub lacnic_read_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = ( fullinfo => '' );

    print $sock "$ip\n" or Carp::carp "write failed: $!";

    while ( defined( my $line = _readline_with_timeout($sock) ) ) {
        local $_ = $line;
        $query{fullinfo} .= $_;
        close $sock
          and return ( permission => 'denied' )
          if /^\%201/ || /^\% Query rate limit exceeded/ || /^\% Not assigned to LACNIC/ || /\% Permission denied/;
        if (/^\% (\S+) resource:/) {
            my $srv = $1;
            close $sock and return () if $srv !~ /lacnic|brazil/i;
        }
        next if ( /^\%/ || !/\:/ );
        s/\s+$//;
        my ( $field, $value ) = split( /:/, $_, 2 );
        $value =~ s/^\s+//;
        next if $field eq 'country' && $query{country};
        $query{ lc($field) } .= ( $query{ lc($field) } ? ' ' : '' ) . $value;
    }
    close $sock;
    return %query;
}

sub lacnic_process_query (%) {
    my %query = @_;

    return () if !$query{inetnum} && !$query{inet6num};

    $query{permission} = 'allowed';
    $query{descr}      = $query{owner};
    $query{netname}    = $query{ownerid};
    $query{source}     = 'LACNIC';
    if ( $query{inetnum} ) {
        $query{cidr}    = $query{inetnum};
        $query{inetnum} = ( Net::CIDR::cidr2range( $query{cidr} ) )[0];
    }
    elsif ( $query{inet6num} ) {
        $query{cidr} = [ Net::CIDR::range2cidr( uc( $query{inet6num} ) ) ];
    }
    unless ( $query{country} ) {
        if ( $query{nserver} && $query{nserver} =~ /\.(\w\w)$/ ) {
            $query{country} = uc $1;
        }
        elsif ( $query{descr} && $query{descr} =~ /\s(\w\w)$/ ) {
            $query{country} = uc $1;
        }
        else {
            return ();
        }
    }
    return %query;
}

sub lacnic_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = lacnic_read_query( $sock, $ip );

    return lacnic_process_query(%query);
}

*afrinic_read_query = *apnic_read_query;

sub afrinic_process_query (%) {
    my %query = @_;

    return ()
      if defined $query{remarks} && $query{remarks} =~ /country is really worldwide/
      or defined $query{descr}   && $query{descr} =~ /Here for in-addr\.arpa authentication/;

    if ( !$query{inet6num} && !$query{inetnum} ) {
        return ();
    }

    $query{permission} = 'allowed';
    $query{cidr} =
      [ Net::CIDR::range2cidr( uc( $query{inet6num} || $query{inetnum} ) ) ];
    return %query;
}

sub afrinic_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = afrinic_read_query( $sock, $ip );

    return afrinic_process_query(%query);
}

sub jpnic_read_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = ( fullinfo => '' );
    print $sock "$ip/e\n" or Carp::carp "write failed: $!";    # /e requests English output

    # JPNIC uses bracket-style fields: "a. [Network Number] 1.2.3.0/24"
    # and also standard "key: value" lines
    my %field_map = (
        'network number'    => 'inetnum',
        'network name'      => 'netname',
        'organization name' => 'descr',
    );
    while ( defined( my $line = _readline_with_timeout($sock) ) ) {
        local $_ = $line;
        $query{fullinfo} .= $_;
        close $sock and return ( permission => 'denied' ) if /^\%201|ERROR:201/;
        next if /^\%/ || /^\#/;
        next if /^\[ .+ \]\s*$/;    # skip banner lines like "[ JPNIC database... ]"
        s/\s+$//;

        # bracket-style: "a. [Field Name]  value" or "[Field Name]  value"
        if ( /^(?:\w+\.\s+)?\[(.+?)\]\s+(.+)/ ) {
            my ( $field, $value ) = ( lc($1), $2 );
            $value =~ s/^\s+//;
            my $mapped = $field_map{$field} || $field;
            $query{$mapped} .= ( $query{$mapped} ? ' ' : '' ) . $value;
            next;
        }

        # standard colon-separated
        next unless /\:/;
        my ( $field, $value ) = split( /:/, $_, 2 );
        $value =~ s/^\s+//;
        $query{ lc($field) } .= ( $query{ lc($field) } ? ' ' : '' ) . $value;
    }
    close $sock;
    return %query;
}

sub jpnic_process_query (%) {
    my %query = @_;

    return () if !$query{inetnum} && !$query{inet6num};

    $query{permission} = 'allowed';
    $query{source}     = 'JPNIC';

    if ( $query{inetnum} && $query{inetnum} =~ m{/} ) {
        # Already in CIDR notation
        $query{cidr} = [ $query{inetnum} ];
    }
    elsif ( $query{inetnum} || $query{inet6num} ) {
        $query{cidr} = [ Net::CIDR::range2cidr( uc( $query{inet6num} || $query{inetnum} ) ) ];
    }

    return %query;
}

sub jpnic_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = jpnic_read_query( $sock, $ip );
    return jpnic_process_query(%query);
}

# KRNIC uses colon-separated format similar to APNIC
*krnic_read_query = *apnic_read_query;

sub krnic_process_query (%) {
    my %query = @_;

    return () if !$query{inetnum} && !$query{inet6num} && !$query{'ipv4 address'};

    $query{permission} = 'allowed';
    $query{source}     = 'KRNIC';

    # KRNIC may use 'ipv4 address' instead of 'inetnum'
    $query{inetnum} ||= $query{'ipv4 address'} if $query{'ipv4 address'};

    if ( $query{inetnum} || $query{inet6num} ) {
        $query{cidr} = [ Net::CIDR::range2cidr( uc( $query{inet6num} || $query{inetnum} ) ) ];
    }

    return %query;
}

sub krnic_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = krnic_read_query( $sock, $ip );
    return krnic_process_query(%query);
}

# IDNIC uses RPSL-like format similar to APNIC
*idnic_read_query = *apnic_read_query;

sub idnic_process_query (%) {
    my %query = @_;

    return () if !$query{inetnum} && !$query{inet6num};

    $query{permission} = 'allowed';
    $query{source}     = 'IDNIC';
    $query{cidr} = [ Net::CIDR::range2cidr( uc( $query{inet6num} || $query{inetnum} ) ) ];

    return %query;
}

sub idnic_query ($$) {
    my ( $sock, $ip ) = @_;

    my %query = idnic_read_query( $sock, $ip );
    return idnic_process_query(%query);
}

sub is_mine ($$;@) {
    my ( $self, $ip, @cidr ) = @_;

    return 0 unless is_valid_ip($ip);
    if ( !scalar @cidr ) {
        my $out = $self->cidr();
        @cidr = @$out if ref $out;
    }

    @cidr = map {
        if (/:/) {
            $_;    # IPv6 CIDR — no padding needed
        }
        else {
            my @dots = ( split /\./ );
            my $pad = '.0' x ( 4 - @dots );
            s|(/.*)|$pad$1|;
            $_;
        }
      }
      map  { split(/\s+/) }
      grep { defined $_ } @cidr;

    return Net::CIDR::cidrlookup( $ip, @cidr );
}

1;

__END__

=head1 NAME

Net::Whois::IANA - A universal WHOIS data extractor.

=head1 SYNOPSIS

  use Net::Whois::IANA;
  my $ip = '132.66.16.2';
  my $iana = Net::Whois::IANA->new;
  $iana->whois_query(-ip=>$ip);
  print "Country: " , $iana->country()            , "\n";
  print "Netname: " , $iana->netname()            , "\n";
  print "Descr: "   , $iana->descr()              , "\n";
  print "Status: "  , $iana->status()             , "\n";
  print "Source: "  , $iana->source()             , "\n";
  print "Server: "  , $iana->server()             , "\n";
  print "Inetnum: " , $iana->inetnum()            , "\n";
  print "CIDR: "    , join(",", $iana->cidr())    , "\n";


=head1 ABSTRACT

This is a simple module to extract the descriptive whois
information about various IPs as they are stored in the regional
whois registries of IANA - RIPE (Europe, Middle East)
APNIC (Asia/Pacific), ARIN (North America), AFRINIC (Africa)
and LACNIC (Latin American & Caribbean) - as well as National
Internet Registries (NIRs): JPNIC (Japan), KRNIC (Korea),
and IDNIC (Indonesia).

It is designed to serve statistical harvesters of various
access logs and likewise, therefore it only collects partial
and [rarely] unprecise information.

=head1 DESCRIPTION

Various Net::Whois and IP:: modules have been created.
This is just something I had to write because none of them
suited my purpose. It is conceptually based on Net::Whois::IP
by Ben Schmitz <bschmitz@orbitz.com>, but differs from it by
a few points:

=over

=item It is object-oriented.

=item It has a few immediate methods for representing some whois fields.

=item It allows the user to specify explicitly which whois servers
to query, and those servers might even not be among the IANA
registries mentioned above.

=item It has more robust error handling.

=back

Net::Whois::IANA was designed to provide a mechanism to lookup
whois information and store most descriptive part of it (descr,
netname and country fields) in the object. This mechanism is
supposed to be attached to a log parser (for example an Apache
web server log) to provide various accounting and statistics
information.

The query is performed in a roundrobin system over all
registries until a valid entry is found. The valid entry stops
the main query loop and the object with information is returned.
Unfortunately, the output formats of each one of the registries
is not completely the same and sometimes even unsimilar but
some common ground was always found and the assignment of the
information into the query object is based upon this common
ground, whatever misleading it might be.

The query to the RIPE and APNIC registries are always performed
with a '-r' flag to avoid blocking of the querying IP. Thus, the
contact info for the given entry is not obtainable with this
module. The query to the ARIN registry is performed with a '+'
flag to force the colon-separated output of the information.

=head1 METHODS

For the convenience of the user, basic list of IANA servers
(@IANA) and their mapping to host names and ports (%IANA) are
being exported.

Also the following methods are being exported:

=head2 $iana->whois_query

Perform the query on the ip specified by $ip. You can limit
the lookup to a single server (of the IANA list) by specifying
'-whois=>$whois' pair or you can provide a set of your own
servers by specifying the '-mywhois=>\%mywhois' pair. The latter
one overrides all of the IANA list for lookup. You can also set
-debug option in order to trigger some verbosity in the output.

    $iana->whois_query(-ip=>$ip,-whois=>$whois|-mywhois=>\%mywhois)

B<Note>: when using C<-mywhois>, each custom source entry may include
a code reference at position 3 to handle the query protocol.  If omitted
(or C<undef>), the module falls back to ARIN protocol (C<"+ $ip\n">).
Make sure this is appropriate for your target server.

=head2 $iana->descr()

Returns some of the "descr:" field contents of the queried IP.

=head2 $iana->netname()

Returns the "netname:" field contents of the queried IP.

=head2 $iana->country()

Returns "country:" field contents of the queried IP. Useful
to combine with the Geography::Countries module.

=head2 $iana->inetnum()

Returns the IP range of the queried IP. Often it is contained
within the inetnum field, but it is calculated for LACNIC.

=head2 $iana->status()

Returns the "status:" field contents of the queried IP.

=head2 $iana->source()

Returns the "source:" field contents of the queried IP.

=head2 $iana->server()

Returns the server that returned most valuable contents of
the queried IP.

=head2 $iana->cidr()

Returns an array in CIDR notation (1.2.3.4/5) of the IP's registered range.

=head2 $iana->fullinfo()

Returns the complete output of the query.

=head2 $iana->is_mine($ip,@cidrrange)

Checks if the ip is within one of the CIDR ranges given by
@cidrrange. Returns 0 if none, 1 if a range matches.

=head2 $iana->abuse()

Yields the best guess for the potential abuse report email address
candidate. This is not a very reliable thing, but sometimes it proves
useful.

=head1 BUGS

As stated many times before, this module is not completely
homogeneous and precise because of the differences between
outputs of the IANA servers and because of some inconsistencies
within each one of them. Its primary target is to collect info
for general, shallow statistical purposes. The is_mine() method
might be optimized.

=head1 TIMEOUTS

The per-source timeout (third element of each server triple in C<%IANA>,
default 30 seconds) governs both the connect attempt and the per-read
deadline. If a whois server stalls mid-response, the read aborts with a
warning rather than blocking indefinitely. To raise or lower the read
deadline for a custom source, set the third element of the server triple
when calling C<whois_query> with C<-mywhois>.

=head1 CAVEATS

The introduction of AFRINIC server may create some confusion
among servers. It might be that some entries are existant either in
both ARIN and AFRINIC or in both RIPE and AFRINIC, and some do not
exist at all. Moreover, there is a border confusion between Middle
East and Africa, thus, some Egypt sites appear under RIPE and some
under AFRINIC. LACNIC server arbitrarily imposes query rate temporary
block. ARIN "subconciously" redirects the client to appropriate
server sometimes. This redirection is not reflected yet by the package.

=head1 SEE ALSO

=over

=item Net::Whois::IP

=item Net::Whois::RIPE

=item IP::Country

=item Geography::Countries

=item Net::CIDR

=item NetAddr::IP

=back

=cut
