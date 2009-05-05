use strict;
use warnings;

use inc::Module::Install;

name 'Authen-CAS-Client';
all_from 'lib/Authen/CAS/Client.pm';
license 'BSD';

requires 'LWP'         => '0.00';
requires 'URI'         => '0.00';
requires 'XML::LibXML' => '0.00';

test_requires 'Test::MockObject' => '0.00';
test_requires 'Test::More'       => '0.00';

auto_install;
WriteAll;
