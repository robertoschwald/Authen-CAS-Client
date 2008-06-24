require 5.006_001;

use strict;
use warnings;

# $Id: Response.pm 26 2008-06-24 15:32:22Z jhord $

#======================================================================
# Authen::CAS::Client::Response
#
package Authen::CAS::Client::Response;

our $VERSION = '0.02';

sub new {
  my ( $class, %args ) = @_;

  my $self = { };
  $self->{$_} = $args{$_}
    for keys %args;

  bless $self, $class
}

sub is_error   { my ( $self ) = @_; ! defined $self->{_ok} }
sub is_failure { my ( $self ) = @_;   defined $self->{_ok} && ! $self->{_ok} }
sub is_success { my ( $self ) = @_;   defined $self->{_ok} &&   $self->{_ok} }


#======================================================================
# Authen::CAS::Client::Response::Error
#
package Authen::CAS::Client::Response::Error;

use base qw/ Authen::CAS::Client::Response /;

sub new {
  my ( $class, %args ) = @_;

  $class->SUPER::new(
    _ok   => undef,
    error => defined $args{error} ? $args{error} : 'An internal error ocurred',
  );
}

sub error { my ( $self ) = @_; $self->{error} }


#======================================================================
# Authen::CAS::Client::Response::Failure
#
package Authen::CAS::Client::Response::Failure;

use base qw/ Authen::CAS::Client::Response /;

sub new {
  my ( $class, %args ) = @_;

  $class->SUPER::new(
    _ok      => 0,
    code     => $args{code},
    message  => defined $args{message} ? $args{message} : '',
  );
}

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

sub _ATTR () { }

sub new {
  my ( $class, %args ) = @_;

  my %attr = $class->_ATTR;
  for ( keys %attr ) {
    $attr{$_} = $args{$_}
      if exists $args{$_};
  }

  $class->SUPER::new( _ok => 1, %attr );
}


#======================================================================
# Authen::CAS::Client::Response::AuthSuccess
#
package Authen::CAS::Client::Response::AuthSuccess;

use base qw/ Authen::CAS::Client::Response::Success /;

sub _ATTR () { ( user => undef, iou => undef, proxies => [ ] ) }

sub user    { my ( $self ) = @_; $self->{user} }
sub iou     { my ( $self ) = @_; $self->{iou} }
sub proxies { my ( $self ) = @_; wantarray ? @{ $self->{proxies} } : [ @{ $self->{proxies} } ] }


#======================================================================
# Authen::CAS::Client::Response::ProxySuccess
#
package Authen::CAS::Client::Response::ProxySuccess;

use base qw/ Authen::CAS::Client::Response::Success /;

sub _ATTR() { ( pt => undef ) }

sub proxy_ticket { my ( $self ) = @_; $self->{pt} }


1;

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

=item new %ARGS

new() creates an instance of an C<Authen::CAS::Client::Response> object
and assigns its data members according to the values in C<%ARGS>.

=item is_error

is_error() returns true if the response represents an error object.

=item is_failure

is_failure() returns true if the response represents a failure object.

=item is_success

is_success() returns true if the response represents a success object.

=back

=head2 Authen::CAS::Client::Response::Error

C<Authen::CAS::Client::Response::Error> is used when an error occurs that
prevents further processing of a request.  This would include not being able
connect to the CAS server, receiving an unexpected response from the server
or being unable to correctly parse the server's response according to the
guidelines in the CAS protocol specification.

=over 2

=item new $ERROR

new() creates an instance of an C<Authen::CAS::Client::Response::Error>
object.  C<$ERROR> is the error string.

=item error

error() returns the error string.

=back

=head2 Authen::CAS::Client::Response::Failure

C<Authen::CAS::Client::Response::Failure> is used as a base class for other
failure responses.  These correspond to the C<cas:authenticationFailure> and
C<cas:proxyFailure> server responses outlined in the CAS protocol
specification.

=over 2

=item new $CODE, $MESSAGE

new() creates an instance of an C<Authen::CAS::Client::Response::Failure>
object.  C<$CODE> is the failure code.  C<$MESSAGE> is the failure message.

=item code

code() returns the failure code.

=item message

message() returns the failure message.

=back

=head2 Authen::CAS::Client::Response::AuthFailure

C<Authen::CAS::Client::Response::AuthFailure> is used when a
C<cas:authenticationFailure> response is received from the CAS server
during a validation attempt.  When using the CAS v2.0 protocol,
C<$CODE> and C<$MESSAGE> are set according to what is parsed from the
server response.  When using the CAS v1.0 protocol, C<$CODE> is set
to 'V10_AUTH_FAILURE' and C<$MESSAGE> is set to the empty string.

No additional methods are defined.

=head2 Authen::CAS::Client::Response::ProxyFailure

C<Authen::CAS::Client::Response::ProxyFailure> is used when a
<cas:proxyFailure> response is received from the CAS server
during a proxy attempt.  C<$CODE> and C<$MESSAGE> are set according
to what is parsed from the server response.

=head2 Authen::CAS::Client::Response::Success

C<Authen::CAS::Client::Response::Success> is used as base class for other
success responses.  These correspond to the C<cas:authenticationSuccess> and
C<cas:proxySuccess> server responses.

No additional methods are defined.

=head2 Authen::CAS::Client::Response::AuthSuccess

C<Authen::CAS::Client::Response::AuthSuccess> is used when a
C<cas:authenticationSuccess> response is received from the CAS server
during a validation attempt.

=over 2

=item user

user() returns the user name that was contained in the server response.

=item iou

iou() returns the proxy granting ticket IOU, if it was present in the
server response.  Otherwise it is set to C<undef>.

=item proxies

proxies() returns the list of proxies present in the server response.  If
no proxies are found, an empty list is returned.  In scalar context an
array reference will be returned instead.

=back

=head2 Authen::CAS::Client::Response::ProxySuccess

C<Authen::CAS::Client::Response::ProxySuccess> is used when a
C<cas:proxySuccess> response is received from the CAS server during
a proxy attempt.

=over 2

=item proxy_ticket

proxy_ticket() returns the proxy ticket that was contained in the
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

Copyright (c) 2007, 2008, jason hord

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
