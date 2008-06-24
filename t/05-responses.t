#!perl -T

use lib '.';

use Test::More tests => 57;

use Authen::CAS::Client::Response;


# inheritance and is_* checking
{
  my %r = (
    ''           => { e => 1, f => 0, s => 0, i => [ ] },
    Error        => { e => 1, f => 0, s => 0, i => [ '' ] },
    Failure      => { e => 0, f => 1, s => 0, i => [ '' ] },
    AuthFailure  => { e => 0, f => 1, s => 0, i => [ '', 'Failure' ] },
    ProxyFailure => { e => 0, f => 1, s => 0, i => [ '', 'Failure' ] },
    Success      => { e => 0, f => 0, s => 1, i => [ '' ] },
    AuthSuccess  => { e => 0, f => 0, s => 1, i => [ '', 'Success' ] },
    ProxySuccess => { e => 0, f => 0, s => 1, i => [ '', 'Success' ] },
  );

  for my $n ( keys %r ) {
    my $t = _n( $n );
    my $o = $t->new();

    isa_ok( $o, _n( $_ ), $t )
      for @{ $r{$n}->{i} };
    isa_ok( $o, $t, $t );

    ok( _tf( $o->$_() ) == _tf( $r{$n}->{ substr $_, 3, 1 } ), "$t->$_()" )
      for qw/ is_error is_failure is_success /;
  }
}


# error object checking
{
  my $o = Authen::CAS::Client::Response::Error->new();
  ok( $o->error() eq 'An internal error ocurred', 'Authen::CAS::Client::Response::Error: error' );
}

{
  my $o = Authen::CAS::Client::Response::Error->new( error => 'ERROR' );
  ok( $o->error() eq 'ERROR', 'Authen::CAS::Client::Response::Error: error' );
}

# failure object checking
{
  my $o = Authen::CAS::Client::Response::Failure->new();
  ok( ! defined $o->code(), 'Authen::CAS::Client::Response::Failure: code' );
  ok( $o->message eq '', 'Authen::CAS::Client::Response::Failure: message' );
}

{
  my $o = Authen::CAS::Client::Response::Failure->new( code => 'CODE', message => 'MESSAGE' );
  ok( $o->code() eq 'CODE', 'Authen::CAS::Client::Response::Failure: code' );
  ok( $o->message eq 'MESSAGE', 'Authen::CAS::Client::Response::Failure: message' );
}

# success object checking
{
  my $o = Authen::CAS::Client::Response::AuthSuccess->new();
  ok( ! defined $o->user(), 'Authen::CAS::Client::Response::AuthSuccess: user' );
  ok( ! defined $o->iou(), 'Authen::CAS::Client::Response::AuthSuccess: iou' );
  ok( @{ $o->proxies() } == 0, 'Authen::CAS::Client::Response::AuthSuccess: proxies' );
}

{
  my $o = Authen::CAS::Client::Response::AuthSuccess->new( user => 'USER', iou => 'IOU', proxies => [qw/ foo bar baz /] );
  ok( $o->user() eq 'USER', 'Authen::CAS::Client::Response::AuthSuccess: user' );
  ok( $o->iou() eq 'IOU', 'Authen::CAS::Client::Response::AuthSuccess: iou' );
  ok( join( ':', @{ $o->proxies() } ) eq join( ':', qw/ foo bar baz / ), 'Authen::CAS::Client::Response::AuthSuccess: proxies' );
}

{
  my $o = Authen::CAS::Client::Response::ProxySuccess->new();
  ok( ! defined $o->proxy_ticket(), 'Authen::CAS::Client::Response::ProxySuccess: pt' );
}

{
  my $o = Authen::CAS::Client::Response::ProxySuccess->new( pt => 'PT' );
  ok( $o->proxy_ticket() eq 'PT', 'Authen::CAS::Client::Response::ProxySuccess: pt' );
}


sub _n { join( '::', split( '::', "Authen::CAS::Client::Response::" . shift() ) ) }
sub _tf { shift() ? 1 : 0 }
