#!perl -T

use lib '.';

use Test::More tests => 2;
use t::MockUserAgent;

use Authen::CAS::Client;

sub CAS_SERVER () { 'https://example.com/cas' }


my $mock = Test::MockUserAgent->new();
my $cas = Authen::CAS::Client->new( CAS_SERVER, fatal => 1 );

$mock->_response( 404, 'Not found' );

eval { $cas->validate( 'S', 'T' ) };
ok( UNIVERSAL::isa( $@, 'Authen::CAS::Client::Response::Error' ), "fatal" );
like( $@->error(), qr/^HTTP request failed: \d+: / );
