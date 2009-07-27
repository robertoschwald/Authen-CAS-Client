require 5.006_001;

use strict;
use warnings;

#======================================================================
# Authen::CAS::Client::Response
#
package Authen::CAS::Client::Response;

our $VERSION = '0.03';

sub _ATTRIBUTES () { _ok => undef, doc => undef }

sub new {
  my ( $class, %args ) = @_;

  my %self = $class->_ATTRIBUTES;
  for my $attribute ( keys %self ) {
    $self{$attribute} = $args{$attribute}
      if exists $args{$attribute};
  }

  bless \%self, $class
}

sub is_error   { my ( $self ) = @_; ! defined $self->{_ok} }
sub is_failure { my ( $self ) = @_;   defined $self->{_ok} && ! $self->{_ok} }
sub is_success { my ( $self ) = @_;   defined $self->{_ok} &&   $self->{_ok} }

sub doc        { my ( $self ) = @_; $self->{doc} }


#======================================================================
# Authen::CAS::Client::Response::Error
#
package Authen::CAS::Client::Response::Error;

use base qw/ Authen::CAS::Client::Response /;

sub _ATTRIBUTES () { error => 'An internal error occurred', $_[0]->SUPER::_ATTRIBUTES }

sub new { my $class = shift; $class->SUPER::new( @_, _ok => undef ) }

sub error { my ( $self ) = @_; $self->{error} }


#======================================================================
# Authen::CAS::Client::Response::Failure
#
package Authen::CAS::Client::Response::Failure;

use base qw/ Authen::CAS::Client::Response /;

sub _ATTRIBUTES () { code => undef, message => '', $_[0]->SUPER::_ATTRIBUTES }

sub new { my $class = shift; $class->SUPER::new( @_, _ok => 0 ) }

sub code    { my ( $self ) = @_; $self->{code} }
sub message { my ( $self ) = @_; $self->{message} }


#======================================================================
# Authen::CAS::Client::Response::AuthFailure
#
package Authen::CAS::Client::Response::AuthFailure;

use base qw/ Authen::CAS::Client::Response::Failure /;


#======================================================================
# Authen::CAS::Client::Response::ProxyFailure
#
package Authen::CAS::Client::Response::ProxyFailure;

use base qw/ Authen::CAS::Client::Response::Failure /;


#======================================================================
# Authen::CAS::Client::Response::Success
#
package Authen::CAS::Client::Response::Success;

use base qw/ Authen::CAS::Client::Response /;

sub new { my $class = shift; $class->SUPER::new( @_, _ok => 1 ) }


#======================================================================
# Authen::CAS::Client::Response::AuthSuccess
#
package Authen::CAS::Client::Response::AuthSuccess;

use base qw/ Authen::CAS::Client::Response::Success /;

sub _ATTRIBUTES () { user => undef, iou => undef, proxies => [ ], $_[0]->SUPER::_ATTRIBUTES }

sub user    { my ( $self ) = @_; $self->{user} }
sub iou     { my ( $self ) = @_; $self->{iou} }
sub proxies { my ( $self ) = @_; wantarray ? @{ $self->{proxies} } : [ @{ $self->{proxies} } ] }


#======================================================================
# Authen::CAS::Client::Response::ProxySuccess
#
package Authen::CAS::Client::Response::ProxySuccess;

use base qw/ Authen::CAS::Client::Response::Success /;

sub _ATTRIBUTES () { proxy_ticket => undef, $_[0]->SUPER::_ATTRIBUTES }

sub proxy_ticket { my ( $self ) = @_; $self->{proxy_ticket} }


1
__END__

=head1 NAME

Authen::CAS::Client::Response - A set of classes for implementing
responses from a CAS server

=head1 DESCRIPTION

C<Authen::CAS::Client::Response> implements a base class that is used to
build a hierarchy of response objects that are returned from methods in
L<Authen::CAS::Client>.  Most response objects are meant to encapsulate
a type of response from a CAS server.

=head1 CLASSES AND METHODS

=head2 Authen::CAS::Client::Response

C<Authen::CAS::Client::Response> is the base class from which all other
response classes inherit.  As such it is very primitive and is never
used directly.

=over 2

=item B<new %args>

C<new()> creates an instance of an C<Authen::CAS::Client::Response> object
and assigns its data members according to the values in C<%args>.

=item B<is_error>

C<is_error()> returns true if the response represents an error object.

=item B<is_failure>

C<is_failure()> returns true if the response represents a failure object.

=item B<is_success>

C<is_success()> returns true if the response represents a success object.

=item B<doc>

C<doc()> returns the response document used to create the response object.
For errors and CAS v1.0 requests this will be the raw text response
from the server.  Otherwise an L<XML::LibXML> object will be returned.
This can be used for debugging or retrieving additional information
from the CAS server's response.

=back

=head2 Authen::CAS::Client::Response::Error

C<Authen::CAS::Client::Response::Error> is used when an error occurs that
prevents further processing of a request.  This would include not being able
connect to the CAS server, receiving an unexpected response from the server
or being unable to correctly parse the server's response according to the
guidelines in the CAS protocol specification.

=over 2

=item B<new error =E<gt> $error, doc =E<gt> $doc>

C<new()> creates an instance of an C<Authen::CAS::Client::Response::Error>
object.  C<$error> is the error string.  C<$doc> is the response document.

=item B<error>

C<error()> returns the error string.

=back

=head2 Authen::CAS::Client::Response::Failure

C<Authen::CAS::Client::Response::Failure> is used as a base class for other
failure responses.  These correspond to the C<cas:authenticationFailure> and
C<cas:proxyFailure> server responses outlined in the CAS protocol
specification.

=over 2

=item B<new code =E<gt> $code, message =E<gt> $message, doc =E<gt> $doc>

C<new()> creates an instance of an C<Authen::CAS::Client::Response::Failure>
object.  C<$code> is the failure code.  C<$message> is the failure message.
C<$doc> is the response document.

=item B<code>

C<code()> returns the failure code.

=item B<message>

C<message()> returns the failure message.

=back

=head2 Authen::CAS::Client::Response::AuthFailure

C<Authen::CAS::Client::Response::AuthFailure> is a subclass of
C<Authen::CAS::Client::Response::Failure> and is used when a
validation attempt fails.  When using the CAS v2.0 protocol,
C<$code>, C<$message> and C<$doc> are set according to what is parsed
from the server response.  When using the CAS v1.0 protocol, C<$code>
is set to C<'V10_AUTH_FAILURE'>, C<$message> is set to the empty string
and C<$doc> is set to the server's response content.

No additional methods are defined.

=head2 Authen::CAS::Client::Response::ProxyFailure

C<Authen::CAS::Client::Response::ProxyFailure> is a subclass of
C<Authen::CAS::Client::Response::Failure> and is used when a
C<cas:proxyFailure> response is received from the CAS server
during a proxy attempt.  C<$code>, C<$message> and C<$doc> are set
according to what is parsed from the server response.

No additional methods are defined.

=head2 Authen::CAS::Client::Response::Success

C<Authen::CAS::Client::Response::Success> is used as base class for other
success responses.  These correspond to the C<cas:authenticationSuccess> and
C<cas:proxySuccess> server responses.

=over 2

=item B<new doc =E<gt> $doc>

C<new()> creates an instance of an C<Authen::CAS::Client::Response::Success>
object.  C<$doc> is the response document.

=back

=head2 Authen::CAS::Client::Response::AuthSuccess

C<Authen::CAS::Client::Response::AuthSuccess> is a subclass of
C<Authen::CAS::Client::Response::Success> and is used when
validation succeeds.

=over 2

=item B<new user =E<gt> $user, iou =E<gt> $iou, proxies =E<gt> \@proxies, doc =E<gt> $doc>

C<new()> creates an instance of an C<Authen::CAS::Client::Response::AuthSuccess>
object.  C<$user> is the username received in the response.  C<$iou>
is the proxy granting ticket IOU, if present.  C<\@proxies> is the
list of proxies used during validation, if present.  C<$doc> is the
response document.

=item B<user>

C<user()> returns the user name that was contained in the server response.

=item B<iou>

C<iou()> returns the proxy granting ticket IOU, if it was present in the
server response.  Otherwise it is set to C<undef>.

=item B<proxies>

C<proxies()> returns the list of proxies present in the server response.  If
no proxies are found, an empty list is returned.  In scalar context an
array reference will be returned instead.

=back

=head2 Authen::CAS::Client::Response::ProxySuccess

C<Authen::CAS::Client::Response::ProxySuccess> is a subclass of
C<Authen::CAS::Client::Response::Success> and is used when a
C<cas:proxySuccess> response is received from the CAS server during
a proxy attempt.

=over 2

=item B<new proxy_ticket =E<gt> $proxy_ticket, doc =E<gt> $doc>

C<new()> creates an instance of an C<Authen::CAS::Client::Response::ProxySuccess>
object.  C<$proxy_ticket> is the proxy ticket received in the response.
C<$doc> is the response document.

=item B<proxy_ticket>

C<proxy_ticket()> returns the proxy ticket that was contained in the
server response.

=back

=head1 BUGS

None are known at this time, but if you find one, please feel free to
submit a report to the author.

=head1 AUTHOR

jason hord E<lt>pravus@cpan.orgE<gt>

=head1 SEE ALSO

=over 2

=item L<Authen::CAS::Client>

=back

=head1 COPYRIGHT

Copyright (c) 2007-2009, jason hord

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

=over 2

=item *

Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

=item *

Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following
disclaimer in the documentation and/or other materials provided
with the distribution.

=back

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=cut
