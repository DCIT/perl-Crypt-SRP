use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Crypt::SRP',
    AUTHOR       => 'Karel Miko',
    VERSION_FROM => 'lib/Crypt/SRP.pm',
    ABSTRACT     => 'Secure Remote Protocol',
    PREREQ_PM    => {
      'Test::More'   => 0,
      'Math::BigInt' => 0,
      'Digest::SHA'  => 0,
      'Digest::SHA1' => 0, #XXX-FIXME just workaround as Digest::SHA is buggy when used together with Mojolicious!!!!
    },
);
