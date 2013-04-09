use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Crypt::SRP',
    AUTHOR       => 'Karel Miko',
    VERSION_FROM => 'lib/Crypt/SRP.pm',
    ABSTRACT     => 'Secure Remote Protocol',
    LICENSE      => 'perl',
    PREREQ_PM    => {
      'Test::More'   => 0,
      'Math::BigInt' => '1.991',
      'Digest::SHA'  => 0,
      'MIME::Base64' => 0,
    },
);
