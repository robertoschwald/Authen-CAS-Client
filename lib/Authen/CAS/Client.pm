package Authen::CAS::Client;

# $Id: Client.pm 14 2007-10-29 13:28:59Z jhord $

require 5.006_001;

use strict;
use warnings;

use LWP::UserAgent;
use URI;
use URI::QueryParam;
use XML::LibXML;
use Authen::CAS::Client::Response;

our $VERSION = '0.02';

#======================================================================
# constructor
#

sub new {
  my ( $class, $cas, %args ) = @_;

  my $self = {
    _cas   => URI->new( $cas ),
    _ua    => LWP::UserAgent->new( agent => "WWW-CAS-Service/$VERSION" ),
    _fatal => $args{fatal} ? 1 : 0,
  };

  bless $self, $class;
}


#======================================================================
# private methods
#

sub _error {
  my ( $self, $error ) = @_;

  my $response = Authen::CAS::Client::Response::Error->new( error => $error );
  die $response
    if $self->{_fatal};

  $response;
}

sub _parse_auth_response {
  my ( $self, $xml ) = @_;

  my $root = XML::LibXML->new()->parse_string( $xml );

  my ( $node, $response );

  if( $node = $root->find( '/cas:serviceResponse/cas:authenticationSuccess' )->get_node( 1 ) ) {
    $response = eval {
      my $user = $node->find( './cas:user' )->get_node( 1 )->textContent();

      my $iou = $node->find( './cas:proxyGrantingTicket' )->get_node( 1 );
      $iou = $iou->textContent()
        if( defined $iou );

      my $proxies = $node->findnodes( './cas:proxies/cas:proxy' );
      $proxies = [ map $_->textContent(), @$proxies ]
        if defined @$proxies;

      Authen::CAS::Client::Response::AuthSuccess->new(
        user    => $user,
        iou     => $iou,
        proxies => $proxies,
      );
    };
    $response = $self->_error( 'Failed to parse authentication success response' )
      if $@;
  }
  elsif( $node = $root->find( '/cas:serviceResponse/cas:authenticationFailure' )->get_node( 1 ) ) {
    $response = eval {
      die
        unless $node->hasAttribute( 'code' );
      my $code = $node->getAttribute( 'code' );
      
      my $message = $node->textContent();
      if( defined $message ) {
        s/^\s+//, s/\s+\z//
          for $message;
      }

      Authen::CAS::Client::Response::AuthFailure->new(
        code    => $code,
        message => $message,
      );
    };
    $response = $self->_error( 'Failed to parse authentication failure response' )
      if $@;
  }
  else {
    die;
  }

  return $response;
}

sub _parse_proxy_response {
  my ( $self, $xml ) = @_;

  my $root = XML::LibXML->new()->parse_string( $xml );

  my ( $node, $response );

  if( $node = $root->find( '/cas:serviceResponse/cas:proxySuccess' )->get_node( 1 ) ) {
    $response = eval {
      my $pt = $node->find( './cas:proxyTicket' )->get_node( 1 )->textContent();

      Authen::CAS::Client::Response::ProxySuccess->new(
        pt => $pt,
      );
    };
    $response = $self->_error( 'Failed to parse proxy success response' )
      if $@;
  }
  elsif( $node = $root->find( '/cas:serviceResponse/cas:proxyFailure' )->get_node( 1 ) ) {
    $response = eval {
      die
        unless $node->hasAttribute( 'code' );
      my $code = $node->getAttribute( 'code' );
      
      my $message = $node->textContent();
      if( defined $message ) {
        s/^\s+//, s/\s+\z//
          for $message;
      }

      Authen::CAS::Client::Response::ProxyFailure->new(
        code    => $code,
        message => $message,
      );
    };
    $response = $self->_error( 'Failed to parse proxy failure response' )
      if $@;
  }
  else {
    die;
  }

  return $response;
}

sub _server_request {
  my ( $self, $path, $params ) = @_;

  my $url      = $self->_url( $path, $params )->canonical();
  my $response = $self->{_ua}->get( $url );

  unless( $response->is_success() ) {
    return $self->_error(
      'HTTP request failed: ' . $response->code() . ': ' . $response->message()
    );
  }

  return $response->content();
}

sub _url {
  my ( $self, $path, $params ) = @_;

  my $url = $self->{_cas}->clone();

  $url->path( $url->path() . $path );
  $url->query_param_append( $_ => $params->{$_} )
    for keys %$params;

  return $url;
}

sub _v20_validate {
  my ( $self, $path, $service, $ticket, %args ) = @_;

  my %params = (
    service => $service,
    ticket  => $ticket,
  );
  $params{renew} = 'true'
    if $args{renew};
  $params{pgtUrl} = URI->new( $args{pgtUrl} )->canonical()
    if defined $args{pgtUrl};

  my $content = $self->_server_request( $path, \%params );
  return $content
    if ref $content;

  my $response = eval{ $self->_parse_auth_response( $content ) };
  return $self->_error( 'Failed to parse server response' )
    if $@;

  return $response;
}


#======================================================================
# public methods
#

sub login_url {
  my ( $self, $service, %args ) = @_;

  my %params = (
    service => $service,
  );
  for ( qw/ renew gateway / ) {
    $params{$_} = 'true', last
      if $args{$_};
  }

  return $self->_url( '/login', \%params )->canonical();
}

sub logout_url {
  my ( $self, %args ) = @_;

  my %params;
  $params{url} = $args{url}
    if defined $args{url};

  return $self->_url( '/logout', \%params )->canonical();
}

sub validate {
  my ( $self, $service, $ticket, %args ) = @_;

  my %params = (
    service => $service,
    ticket  => $ticket,
  );
  $params{renew} = 'true'
    if $args{renew};

  my $content = $self->_server_request( '/validate', \%params );
  return $content
    if ref $content;

  return $self->_error('Server sent an invalid response')
    unless $content =~ /^(yes|no)\n(.*)\n$/;

  my ( $yn, $user ) = ( $1, $2 );
  return Authen::CAS::Client::Response::AuthFailure->new( code => 'V10_AUTH_FAILURE' ),
    unless $yn eq 'yes';

  return Authen::CAS::Client::Response::AuthSuccess->new( user => $user );
}

sub service_validate {
  my ( $self, $service, $ticket, %args ) = @_;
  return $self->_v20_validate( '/serviceValidate', $service, $ticket, %args );
}

sub proxy_validate {
  my ( $self, $service, $ticket, %args ) = @_;
  return $self->_v20_validate( '/proxyValidate', $service, $ticket, %args );
}

sub proxy {
  my ( $self, $pgt, $target ) = @_;

  my %params = (
    pgt           => $pgt,
    targetService => URI->new( $target ),
  );

  my $content = $self->_server_request( '/proxy', \%params );
  return $content
    if ref $content;

  my $response = eval { $self->_parse_proxy_response( $content ) };
  return $self->_error( 'Failed to parse server response' )
    if $@;

  return $response;
}


1;

__END__

=head1 NAME

Authen::CAS::Client - Provides an easy-to-use interface for authentication
using JA-SIG's Central Authentication Service

=head1 SYNOPSIS

  use Authen::CAS::Client;

  my $cas = Authen::CAS::Client->new( 'https://example.com/cas' );


  # generate an HTTP redirect to the CAS login URL
  my $r = HTTP::Response->new( 302 );
  $r->header( Location => $cas->login_url() );


  # generate an HTTP redirect to the CAS logout URL
  my $r = HTTP::Response->new( 302 );
  $r->header( Location => $cas->logout_url() );


  # validate a service ticket (CAS v1.0)
  my $r = $cas->validate( $service, $ticket );
  if( $r->is_success() ) {
    print "User authenticated as: ", $r->user(), "\n";
  }

  # validate a service ticket (CAS v2.0)
  my $r = $cas->service_validate( $service, $ticket );
  if( $r->is_success() ) {
    print "User authenticated as: ", $r->user(), "\n";
  }


  # validate a service/proxy ticket (CAS v2.0)
  my $r = $cas->proxy_validate( $service, $ticket );
  if( $r->is_success() ) {
    print "User authenticated as: ", $r->user(), "\n";
    print "Proxied through:\n";
    print "  $_\n"
      for $r->proxies();
  }


  # validate a service ticket and request a proxy ticket (CAS v2.0)
  my $r = $cas->service_validate( $server, $ticket, pgtUrl => $url );
  if( $r->is_success() ) {
    print "User authenticated as: ", $r->user(), "\n";

    unless( defined $r->iou() ) {
      print "Service validation for proxying failed\n";
    }
    else {
      print "Proxy granting ticket IOU: ", $r->iou(), "\n";

      ...
      # map IOU to proxy granting ticket via request to pgtUrl
      ...

      $r = $cas->proxy( $pgt, $target_service );
      if( $r->is_success() ) {
        print "Proxy ticket issued: ", $r->proxy_ticket(), "\n";
      }
    }
  }

=head1 DESCRIPTION

The C<Authen::CAS::Client> module provides a simple interface for
authenticating users using JA-SIG's CAS protocol.  Both CAS v1.0
and v2.0 are supported.

=head1 METHODS

=over 2

=item new $URL [, %ARGS]

new() creates an instance of an C<Authen::CAS::Client> object.  C<$URL>
refers to the CAS server's base URL.  C<%ARGS> may contain the
following optional parameter:

=over 4

=item * fatal =E<gt> $BOOLEAN

If this argument is true, the CAS client will C<die()> with an
C<Authen::CAS::Client::Response::Error> object whenever an error
occurs.  Otherwise an C<Authen::CAS::Client::Response::Error>
object is returned, instead.  See L<Authen::CAS::Client::Response>
for more detail on response objects.

=back

=item login_url $SERVICE [, %ARGS]

login_url() returns the CAS server's login URL which can be used to
redirect users to start the authentication process.  C<$SERVICE> is the
service identifier that will be used during validation requests.
C<%ARGS> may contain the following optional parameters:

=over 4

=item * renew =E<gt> $BOOLEAN

This causes the CAS server to force a user to re-authenticate even if
an SSO session is already present for that user.

=item * gateway =E<gt> $BOOLEAN

This causes the CAS server to only rely on SSO sessions for authentication.
If an SSO session is not available for the current user, validation
will result in a failure.

=back

=item logout_url [%ARGS]

logout_url() returns the CAS server's logout URL which can be used to
redirect users to end authenticated sessions.  C<%ARGS> may contain
the following optional parameter:

=over 4

=item * url =E<gt> $URL

If present, the CAS server will present the user with a link to the given
URL once the user has logged out.

=back

=item validate $SERVICE, $TICKET [, %ARGS]

validate() attempts to validate a service ticket using the CAS v1.0 protocol.
C<$SERVICE> is the service identifier that was passed to the CAS server
during the login process.  C<$TICKET> is the service ticket that was
received after a successful authentication attempt.  Returns an appropriate
L<Authen::CAS::Response> object.  C<%ARGS> may contain the following optional
parameter:

=over 4

=item * renew =E<gt> $BOOLEAN

This will cause the CAS server to respond with a failure if authentication
validation was done via a CAS SSO session.

=back

=item service_validate $SERVICE, $TICKET [, %ARGS]

service_validate() attempts to validate a service ticket using the CAS v2.0
protocol.  This is similar to C<validate()>, but allows for greater
flexibility when there is a need for proxying authentication to back-end
services.  The C<$SERVICE> and C<$TICKET> parameters are the same as above.
Returns an appropriate L<Authen::CAS::Response> object.  C<%ARGS> may
contain the following optional parameters:

=over 4

=item * renew =E<gt> $BOOLEAN

This will cause the CAS server to respond with a failure if authentication
validation was done via a CAS SSO session.

=item * pgtUrl =E<gt> $URL

This tells the CAS server that a proxy ticket needs to be issued for
proxying authentication to a back-end service.  C<$URL> corresponds to
a callback URL that the CAS server will use to verify the service's
identity.  Per the CAS specification, this URL must be HTTPS.  If this
verification fails, normal validation will occur, but a proxy granting
ticket IOU will not be issued.

Also note that this call will block until the CAS server completes its
service verification attempt.  The returned proxy granting ticket IOU
can then be used to retrieve the proxy granting ticket that was passed
as a parameter to the given URL.

=back

=item proxy_validate $SERVICE, $TICKET [, %ARGS]

proxy_validate() is almost identical in operation to C<service_validate()>
except that both service tickets and proxy tickets can be used for
validation and a list of proxies will be provided if proxied authentication
has been used.  The C<$SERVICE> and C<$TICKET> parameters are the same as
above.  Returns an appropriate L<Authen::CAS::Response> object.  C<%ARGS>
may contain the following optional parameters:

=over 4

=item * renew =E<gt> $BOOLEAN

This is the same as described above.

=item * pgtUrl =E<gt> $URL

This is the same as described above.

=back

=item proxy $PGT, $TARGET

proxy() is used to retrieve a proxy ticket that can be passed to a back-end
service for proxied authentication.  C<$PGT> is the proxy granting ticket
that was passed as a parameter to the C<pgtUrl> specified in either
C<service_validate()> or C<proxy_validate()>.  C<$TARGET> is the
service identifier for the back-end system that will be using the
returned proxy ticket for validation.  Returns an appropriate
L<Authen::CAS::Response> object.

=back

=head1 BUGS

None are known at this time, but if you find one, please feel free to
submit a report to the author.

=head1 AUTHOR

jason hord E<lt>pravus@cpan.orgE<gt>

=head1 SEE ALSO

L<Authen::CAS::Client::Response>

More information about CAS can be found at JA-SIG's CAS homepage:
L<http://www.ja-sig.org/products/cas/>

=head1 COPYRIGHT

Copyright (c) 2007, jason hord

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
