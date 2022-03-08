# NAME

Net::Whois::IANA - Net::Whois::IANA - A universal WHOIS data extractor.

# VERSION

version 0.48

# SYNOPSIS

```perl
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
```

# DESCRIPTION

Various Net::Whois and IP:: modules have been created.
This is just something I had to write because none of them s
uited my purpose. It is conceptually based on Net::Whois::IP
by Ben Schmitz <bschmitz@orbitz.com>, but differs from it by
a few points:

- It is object-oriented.
- It has a few immediate methods for representing some whois fields.
- It allows the user to specify explicitly which whois servers
to query, and those servers might even not be of the four main
registries mentioned above.
- It has more robust error handling.

Net::Whois::IANA was designed to provide a mechanism to lookup
whois information and store most descriptive part of it (descr,
netname and country fields) in the object. This mechanism is
supposed to be attached to a log parser (for example an Apache
web server log) to provide various accounting and statistics
information.

The query is performed in a roundrobin system over all four
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

# NAME

Net::Whois::IANA - A universal WHOIS data extractor.

# ABSTRACT

This is a simple module to extract the descriptive whois
information about various IPs as they are stored in the four
regional whois registries of IANA - RIPE (Europe, Middle East)
APNIC (Asia/Pacific), ARIN (North America), AFRINIC (Africa)
and LACNIC (Latin American & Caribbean).

It is designed to serve statistical harvesters of various
access logs and likewise, therefore it only collects partial
and \[rarely\] unprecise information.

# METHODS

For the convenience of the user, basic list of IANA servers
(@IANA) and their mapping to host names and ports (%IANA) are
being exported.

Also the following methods are being exported:

## $iana->whois\_query

Perform the query on the ip specified by $ip. You can limit
the lookup to a single server (of the IANA list) by specifying
'-whois=>$whois' pair or you can provide a set of your own
servers by specifying the '-mywhois=>\\%mywhois' pair. The latter
one overrides all of the IANA list for lookup. You can also set
\-debug option in order to trigger some verbosity in the output.

```perl
$iana->whois_query(-ip=>$ip,-whois=>$whois|-mywhois=>\%mywhois)
```

## $iana->descr()

Returns some of the "descr:" field contents of the queried IP.

## $iana->netname()

Returns the "netname:" field contents of the queried IP.

## $iana->country()

Returns "country:" field contents of the queried IP. Useful
to combine with the Geography::Countries module.

## $iana->inetnum()

Returns the IP range of the queried IP. Often it is contained
within the inetnum field, but it is calculated for LACNIC.

## $iana->status()

Returns the "status:" field contents of the queried IP.

## $iana->source()

Returns the "source:" field contents of the queried IP.

## $iana->server()

Returns the server that returned most valuable ntents of
the queried IP.

## $iana->cidr()

Returns an array in CIDR notation (1.2.3.4/5) of the IP's registered range.

## $iana->fullinfo()

Returns the complete output of the query.

## $iana->is\_mine($ip,@cidrrange)

Checks if the ip is within one of the CIDR ranges given by
@cidrrange. Returns 0 if none, 1 if a range matches.

## $iana->abuse()

Yields the best guess for the potential abuse report email address
candidate. This is not a very reliable thing, but sometimes it proves
useful.

# BUGS

As stated many times before, this module is not completely
homogeneous and precise because of the differences between
outputs of the IANA servers and because of some inconsistencies
within each one of them. Its primary target is to collect info
for general, shallow statistical purposes. The is\_mine() method
might be optimized.

# CAVEATS

The introduction of AFRINIC server may create some confusion
among servers. It might be that some entries are existant either in
both ARIN and AFRINIC or in both RIPE and AFRINIC, and some do not
exist at all. Moreover, there is a border confusion between Middle
East and Africa, thus, some Egypt sites appear under RIPE and some
under AFRINIC. LACNIC server arbitrarily imposes query rate temporary
block. ARIN "subconciously" redirects the client to appropriate
server sometimes. This redirection is not reflected yet by the package.

# SEE ALSO

- Net::Whois::IP
- Net::Whois::RIPE
- IP::Country
- Geography::Countries
- Net::CIDR
- NetAddr::IP

# AUTHOR

Roman M. Parparov <roman@parparov.com>, Nicolas R <atoomic@cpan.org>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2003-2013, 2018 by Bolet Consulting <bolet@parparov.com>.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
