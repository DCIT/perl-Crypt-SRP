use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Crypt::SRP',
    AUTHOR       => 'Karel Miko',
    VERSION_FROM => 'lib/Crypt/SRP.pm',
    ABSTRACT     => 'Secure Remote Protocol',
    LICENSE      => 'perl_5',
    PREREQ_PM    => {
      'CryptX'       => '0.029',   # we need: Crypt::Misc + Math::BigInt::LTM (v0.029 = Apr 13, 2016)
      'Math::BigInt' => '1.36',    # we need: use Math::BigInt lib => 'LTM' (v1.36 = Jul 09, 2001)
    },
    MIN_PERL_VERSION => '5.006',
    META_MERGE       => {
      resources => {
        repository => 'https://github.com/DCIT/perl-Crypt-SRP',
      },
    },
    dist => {
      PREOP    => 'pod2text lib/Crypt/SRP.pm > README',
      TARFLAGS => '--owner=0 --group=0 -cvf',
    },
);
