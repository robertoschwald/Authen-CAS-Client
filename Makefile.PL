use strict;
use warnings;

use ExtUtils::MakeMaker;

open TOUCH, '>>', 'META.yml'; close TOUCH;

WriteMakefile(
    NAME          => 'Authen::CAS::Client',
    AUTHOR        => 'jason hord <pravus@cpan.org>',
    VERSION_FROM  => 'lib/Authen/CAS/Client.pm',
    ABSTRACT_FROM => 'lib/Authen/CAS/Client.pm',
    PREREQ_PM => {
      'Carp'             => 0,
      'HTTP::Request'    => 0,
      'LWP::UserAgent'   => 0,
      'Test::More'       => 0,
      'Test::MockObject' => 0,
      'URI'              => 0,
      'XML::LibXML'      => 0,
    },
    dist          => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean         => { FILES => 'Authen-CAS-Client-*' },
);
