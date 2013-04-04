package Crypt::SRP;

# Copyright (c) 2012 DCIT, a.s. [http://www.dcit.cz] - Miko

use strict;
use warnings;

our $VERSION = '0.002';
$VERSION = eval $VERSION;

use Math::BigInt try => 'GMP';
use Digest::SHA  qw(sha1 sha256 sha384 sha512);

### predefined parameters - see http://tools.ietf.org/html/rfc5054 appendix A

use constant predefined_groups => {
    'RFC5054-1024bit' => {
        g => 2,
        N => q[
          EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
          9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
          8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
          7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
          FD5138FE 8376435B 9FC61D2F C0EB06E3
        ],
    },
    'RFC5054-1536bit' => {
        g => 2,
        N => q[
          9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961
          4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843
          80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B
          E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5
          6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A
          F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E
          8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB
        ],
    },
    'RFC5054-2048bit' => {
        g => 2,
        N => q[
          AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
          3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
          CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
          D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
          7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
          436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
          5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
          03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
          94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
          9E4AFF73
        ],
    },
    'RFC5054-3072bit' => {
        g => 5,
        N => q[
          FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
          8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
          302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
          A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
          49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
          FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
          670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
          180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
          3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
          04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
          B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
          1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
          BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
          E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
        ],
    },
    'RFC5054-4096bit' => {
        g => 5,
        N => q[
          FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
          8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
          302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
          A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
          49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
          FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
          670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
          180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
          3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
          04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
          B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
          1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
          BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
          E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
          99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
          04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
          233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
          D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
          FFFFFFFF FFFFFFFF
        ],
    },
    'RFC5054-6144bit' => {
        g => 5,
        N => q[
          FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
          8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
          302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
          A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
          49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
          FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
          670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
          180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
          3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
          04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
          B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
          1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
          BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
          E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
          99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
          04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
          233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
          D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
          36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
          AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
          DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
          2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
          F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
          BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
          CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
          B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
          387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
          6DCC4024 FFFFFFFF FFFFFFFF
        ],
    },
    'RFC5054-8192bit' => {
        g => 19,
        N => q[
          FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
          8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
          302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
          A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
          49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
          FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
          670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
          180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
          3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
          04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
          B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
          1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
          BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
          E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
          99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
          04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
          233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
          D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
          36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
          AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
          DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
          2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
          F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
          BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
          CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
          B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
          387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
          6DBE1159 74A3926F 12FEE5E4 38777CB6 A932DF8C D8BEC4D0 73B931BA
          3BC832B6 8D9DD300 741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C
          5AE4F568 3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
          22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B 4BCBC886
          2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A 062B3CF5 B3A278A6
          6D2A13F8 3F44F82D DF310EE0 74AB6A36 4597E899 A0255DC1 64F31CC5
          0846851D F9AB4819 5DED7EA1 B1D510BD 7EE74D73 FAF36BC3 1ECFA268
          359046F4 EB879F92 4009438B 481C6CD7 889A002E D5EE382B C9190DA6
          FC026E47 9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
          60C980DD 98EDD3DF FFFFFFFF FFFFFFFF
        ],
    },
};

### class constructor

sub new {
  my ($class, $group_params, $hash) = @_;
  my $self = bless {}, $class;

  # setup N and g values
  if ($group_params =~ /RFC5054-(1024|1536|2048|3072|4096|6144|8192)bit$/) {
    my $str = predefined_groups->{$group_params}->{N};
    $str =~ s/[\r\n\s]*//sg;
    $self->{Num_N} = Math::BigInt->from_hex($str);
    $self->{Num_g} = Math::BigInt->new(predefined_groups->{$group_params}->{g});
    $self->{N_LENGTH} = length(_bignum2bytes($self->{Num_N}));
  }
  else {
    die "FATAL: invalid group_params '$group_params'";
  }

  # setup and test hash function
  $self->{HASH} = $hash;
  die "FATAL: invalid hash '$hash'" unless defined $self->_HASH("test");

  return $self;
}

### class PUBLIC methods

sub client_init {
  my ($self, $Bytes_I, $Bytes_P, $Bytes_s) = @_;
  $self->{Bytes_I} = $Bytes_I;
  $self->{Bytes_P} = $Bytes_P;
  $self->{Bytes_s} = $Bytes_s;
  $self->{Num_x} = $self->_calc_x();            # x = _HASH(s | _HASH(I | ":" | P))
}

sub server_init {
  my ($self, $Bytes_I, $Bytes_v, $Bytes_s, $Bytes_A, $Bytes_B, $Bytes_b) = @_;
  $self->{Bytes_I} = $Bytes_I;
  $self->{Num_v} = _bytes2bignum($Bytes_v);
  $self->{Bytes_s} = $Bytes_s;
  $self->{Num_A} = _bytes2bignum($Bytes_A) if defined $Bytes_A;
  $self->{Num_B} = _bytes2bignum($Bytes_B) if defined $Bytes_B;
  $self->{Num_b} = _bytes2bignum($Bytes_b) if defined $Bytes_b;
}

sub client_compute_A {
  my ($self) = @_;
  $self->{Num_a} = $self->_generate_SRP_a;      # a = random() // a has min 256 bits, a < N
  $self->{Num_A} = $self->_calc_A;              # A = g^a % N
  return wantarray ? (_bignum2bytes($self->{Num_A}), _bignum2bytes($self->{Num_a})) : _bignum2bytes($self->{Num_A});
}

sub client_compute_M1 {
  my ($self, $Bytes_B) = @_;
  $self->{Num_B} = _bytes2bignum($Bytes_B);
  $self->{Num_u} = $self->_calc_u;              # u = _HASH(_PAD(A) | _PAD(B))
  $self->{Num_k} = $self->_calc_k;              # k = _HASH(N | _PAD(g))
  $self->{Num_S} = $self->_calc_S_client;       # S = (B - (k * ((g^x)%N) )) ^ (a + (u * x)) % N
  $self->{Bytes_K} = $self->_calc_K;            # K = _HASH( _PAD(S) )
  $self->{Bytes_M1} = $self->_calc_M1;          # M1 = _HASH( _HASH(N) XOR _HASH(_PAD(g)) | _HASH(I) | s | _PAD(A) | _PAD(B) | K )
  return $self->{Bytes_M1};
}

sub client_verify_M2 {
  my ($self, $Bytes_M2) = @_;
  my $M2 = $self->_calc_M2;                     # M2 = _HASH( _PAD(A) | M1 | K )
  return 0 unless $Bytes_M2 eq $M2;
  $self->{Bytes_M2} = $Bytes_M2;
  return 1;
}

sub server_compute_B {
  my ($self) = @_;
  $self->{Num_b} = $self->_generate_SRP_b;      # b = random() // b has min 256 bits, b < N
  $self->{Num_k} = $self->_calc_k;              # k = _HASH(N | _PAD(g))
  $self->{Num_B} = $self->_calc_B;              # B = ( k*v + (g^b % N) ) % N
  return wantarray ? (_bignum2bytes($self->{Num_B}), _bignum2bytes($self->{Num_b})) : _bignum2bytes($self->{Num_B});
}

sub server_verify_M1 {
  my ($self, $Bytes_A, $Bytes_M1) = @_;
  $self->{Num_A} = _bytes2bignum($Bytes_A);
  $self->{Num_u} = $self->_calc_u;              # u = _HASH(_PAD(A) | _PAD(B))
  $self->{Num_S} = $self->_calc_S_server;       # S = ( (A * ((v^u)%N)) ^ b) % N
  $self->{Bytes_K} = $self->_calc_K;            # K = _HASH( _PAD(S) )
  my $M1 = $self->_calc_M1;                     # M1 = _HASH( _HASH(N) XOR _HASH(_PAD(g)) | _HASH(I) | s | _PAD(A) | _PAD(B) | K )
  return 0 unless $Bytes_M1 eq $M1;
  $self->{Bytes_M1} = $Bytes_M1;
  return 1;
}

sub server_compute_M2 {
  my ($self) = @_;
  $self->{Bytes_M2}  = $self->_calc_M2;         # M2 = _HASH( _PAD(A) | M1 | K )
  return $self->{Bytes_M2};
}

sub get_secret_K {
  my ($self) = @_;
  return $self->{Bytes_K};
}

sub get_secret_S {
  my ($self) = @_;
  return _bignum2bytes($self->{Num_S});
}

sub compute_verifier {
  my ($self, $Bytes_I, $Bytes_P, $Bytes_s) = @_;
  $self->client_init($Bytes_I, $Bytes_P, $Bytes_s);
  return $self->_calc_v;
}

sub compute_verifier_and_salt {
  my ($self, $Bytes_I, $Bytes_P, $salt_len) = @_;
  $salt_len = 32 unless defined $salt_len;
  my $Bytes_s = $self->random_bytes($salt_len);
  $self->client_init($Bytes_I, $Bytes_P, $Bytes_s);
  return ($Bytes_s, $self->_calc_v);
}

sub random_bytes {
  my $self = shift;
  my $length = shift || 32;
  my $rv;

  if (eval {require Crypt::OpenSSL::Random}) {
    if (Crypt::OpenSSL::Random::random_status()) {
      $rv = Crypt::OpenSSL::Random::random_bytes($length);
    }
  }
  elsif (eval {require Net::SSLeay}) {
    if (Net::SSLeay::RAND_status() == 1) {
      if (Net::SSLeay::RAND_bytes($rv, $length) != 1) {
        $rv = undef;
      }
    }
  }
  elsif (eval {require Crypt::Random}) {
    $rv = Crypt::Random::makerandom_octet(Length=>$length);
  }
  elsif (eval {require Bytes::Random::Secure}) {
    $rv = Bytes::Random::Secure::random_bytes(32);
  }

  if (!defined $rv)  {
    warn "WARNING: Generating random bytes via insecure rand()\n";
    $rv = pack('C*', map(int(rand(256)), 1..$length));
  }

  return $rv
}

### class PRIVATE methods

sub _HASH {
  my ($self, $data) = @_;
  return sha1($data)   if $self->{HASH} eq 'SHA1';
  return sha256($data) if $self->{HASH} eq 'SHA256';
  return sha384($data) if $self->{HASH} eq 'SHA384';
  return sha512($data) if $self->{HASH} eq 'SHA512';
  return undef;
}

sub _PAD {
  my ($self, $data) = @_;
  return $data if length($data) >= $self->{N_LENGTH};
  return (chr(0) x ($self->{N_LENGTH} - length($data))) . $data;
}

sub _calc_x {
  my $self = shift;
  return undef unless defined $self->{Bytes_I} && defined $self->{Bytes_P} && defined $self->{Bytes_s};
  # x = _HASH(s | _HASH(I | ":" | P))
  my $Bytes_x = $self->_HASH( $self->{Bytes_s} . $self->_HASH($self->{Bytes_I} . ':' . $self->{Bytes_P}) );
  my $Num_x = _bytes2bignum($Bytes_x);
  return $Num_x;
}

sub _calc_v {
  my $self = shift;
  return undef unless defined $self->{Num_x} && defined $self->{Num_N} && defined $self->{Num_g};
  # v = g^x % N
  my $Num_v = Math::BigInt->new($self->{Num_g})->copy->bmodpow($self->{Num_x}, $self->{Num_N});
  my $Bytes_v = _bignum2bytes($Num_v);
  return $Bytes_v;
}

sub _calc_A {
  my $self = shift;
  return undef unless defined $self->{Num_a} && defined $self->{Num_N} && defined $self->{Num_g};
  # A = g^a % N
  my $Num_A = Math::BigInt->new($self->{Num_g})->copy->bmodpow($self->{Num_a}, $self->{Num_N});
  return $Num_A;
}

sub _calc_u {
  my $self = shift;
  return undef unless defined $self->{Num_A} && defined $self->{Num_B};
  # u = _HASH(_PAD(A) | _PAD(B))
  my $Bytes_u = $self->_HASH( $self->_PAD(_bignum2bytes($self->{Num_A})) . $self->_PAD(_bignum2bytes($self->{Num_B})) );
  my $Num_u = _bytes2bignum($Bytes_u);
  return $Num_u;
}

sub _calc_k {
  my $self = shift;
  return undef unless defined $self->{Num_N} && defined $self->{Num_g};
  # k = _HASH(N | _PAD(g))
  my $Num_k = _bytes2bignum( $self->_HASH(_bignum2bytes($self->{Num_N}) . $self->_PAD(_bignum2bytes($self->{Num_g}))) );
  return $Num_k;
}

sub _calc_S_client {
  my $self = shift;
  return undef unless defined $self->{Num_B} && defined $self->{Num_a} && defined $self->{Num_u} && defined $self->{Num_k};
  return undef unless defined $self->{Num_x} && defined $self->{Num_N} && defined $self->{Num_g};
  # S = (B - (k * ((g^x)%N) )) ^ (a + (u * x)) % N
  my $tmp1 = Math::BigInt->new($self->{Num_g})->copy->bmodpow($self->{Num_x}, $self->{Num_N})->bmul($self->{Num_k});
  my $tmp2 = Math::BigInt->new($self->{Num_u})->copy->bmul($self->{Num_x})->badd($self->{Num_a});
  my $Num_S = Math::BigInt->new($self->{Num_B})->bsub($tmp1)->bmodpow($tmp2, $self->{Num_N});
  return $Num_S;
}

sub _calc_S_server {
  my $self = shift;
  return undef unless defined $self->{Num_A} && defined $self->{Num_b} && defined $self->{Num_u};
  return undef unless defined $self->{Num_v} && defined $self->{Num_N};
  # S = ( (A * ((v^u)%N)) ^ b) % N
  my $Num_S = Math::BigInt->new($self->{Num_v})->copy->bmodpow($self->{Num_u}, $self->{Num_N});
  $Num_S->bmul($self->{Num_A})->bmodpow($self->{Num_b}, $self->{Num_N});
  return $Num_S;
}

sub _calc_K {
  my $self = shift;
  return undef unless defined $self->{Num_S};
  # K = _HASH( _PAD(S) )
  my $Bytes_K = $self->_HASH(_bignum2bytes($self->_PAD($self->{Num_S})));
  return $Bytes_K
}

sub _calc_M1 {
  my $self = shift;
  return undef unless defined $self->{Num_A} && defined $self->{Num_B} && defined $self->{Num_N} && defined $self->{Num_g};
  return undef unless defined $self->{Bytes_K} && defined $self->{Bytes_I} && defined $self->{Bytes_s};
  # M1 = _HASH( _HASH(N) XOR _HASH(_PAD(g)) | _HASH(I) | s | _PAD(A) | _PAD(B) | K )
  my $data1 = ($self->_HASH(_bignum2bytes($self->{Num_N})) ^ $self->_HASH($self->_PAD(_bignum2bytes($self->{Num_g})))) . $self->_HASH($self->{Bytes_I});
  my $data2 = $self->{Bytes_s} . $self->_PAD(_bignum2bytes($self->{Num_A})) . $self->_PAD(_bignum2bytes($self->{Num_B})) . $self->{Bytes_K};
  my $Bytes_M1 = $self->_HASH( $data1 . $data2 );
  return $Bytes_M1;
}

sub _calc_M2 {
  my $self = shift;
  return undef unless defined $self->{Bytes_K} && defined $self->{Num_A} && defined $self->{Bytes_M1};
  # M2 = _HASH( _PAD(A) | M1 | K )
  my $Bytes_M2 = $self->_HASH( $self->_PAD(_bignum2bytes($self->{Num_A})) . $self->{Bytes_M1} . $self->{Bytes_K});
  return $Bytes_M2;
}

sub _calc_B {
  my $self = shift;
  return undef unless defined $self->{Num_k} && defined $self->{Num_b} && defined $self->{Num_N} && defined $self->{Num_g};
  # B = ( k*v + (g^b % N) ) % N
  my $tmp = Math::BigInt->new($self->{Num_g})->copy->bmodpow($self->{Num_b}, $self->{Num_N});
  my $Num_B = Math::BigInt->new($self->{Num_k})->copy->bmul($self->{Num_v})->badd($tmp)->bmod($self->{Num_N});
  return $Num_B;
}

sub _generate_SRP_a_or_b {
  my $self = shift;
  my $pre = shift;
  my $min = Math::BigInt->new(256)->bpow(31); # we require minimum 256bits (=32bytes)
  my $max = Math::BigInt->new($self->{Num_N})->copy->bsub(1); # $max = N-1
  if (defined $pre) {
    my $result = $pre;
    die "Invalid (too short) prefefined value" unless $result->bcmp($min) >= 0;
    die "Invalid (too big) prefefined value"   unless $result->bcmp($max) <= 0;
    return $result;
  }
  while(1) {
    my $result = _bytes2bignum($self->random_bytes($self->{N_LENGTH} + 5));
    $result->bmod($max)->badd(1); # 1 <= $result <= N-1
    return $result if $result->bcmp($min) >= 0 # $min <= $result <= N-1
  }
}

sub _generate_SRP_a {
  my $self = shift;
  $self->_generate_SRP_a_or_b($self->{predefined_a});
}

sub _generate_SRP_b {
  my $self = shift;
  $self->_generate_SRP_a_or_b($self->{predefined_b});
}

### helper functions - NOT METHODS!!!

sub _bignum2bytes {
  my $bignum = shift;
  my $hex = $bignum->as_hex;
  $hex =~ s/^0x//;                    # strip leading '0x...'
  $hex = "0$hex" if length($hex) % 2; # add leading '0' if neccessary
  return pack("H*", $hex);
}

sub _bytes2bignum {
  my $bytes = shift;
  return Math::BigInt->from_hex(unpack("H*", $bytes));
}

1;

__END__

=head1 NAME

Crypt::SRP - Secure Remote Protocol (SRP6a)

=head1 SYNOPSIS

Example 1 - creating a new user and his/her password verifier:

 ###CLIENT###
 my $I = '...'; # login entered by user
 my $P = '...'; # password entered by user
 my $cli = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
 my ($s, $v) = $cli->compute_verifier_and_salt($I, $P);

 #  request to server:  ---> /auth/create_user [$I, $s, $v] --->

                           ###SERVER###
                           my %USERS;  # sort of "user database"
                           die "user already exists" unless $USERS{$I};
                           $USERS{$I}->{salt} = $s;
                           $USERS{$I}->{verifier} = $v;

Example 2 - SRP login handshake:

 ###CLIENT###
 my $I = '...'; # login entered by user
 my $P = '...'; # password entered by user
 my $cli = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
 my ($A, $a) = $cli->client_compute_A;

 #  request[1] to server:  ---> /auth/srp_step1 ($I, $A) --->

                           ###SERVER###
                           my %USERS;  # sort of "user database"
                           my %TOKENS; # sort of temporary "token database"
                           my $srv = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
                           my ($B, $b) = $srv->server_compute_B;
                           my $s = $USERS{$I}->{salt};
                           my $token = $srv->random_bytes(32);
                           $TOKENS{$token} = [$I, $A, $b, $B];

 #  response[1] from server:  <--- ($B, $s, $token) <---

 ###CLIENT###
 $cli->client_init($I, $P, $s);
 my $M1 = $cli->client_compute_M1($B)

 #  request[2] to server:  ---> /auth/srp_step2 ($M1, $token) --->

                           ###SERVER###
                           my $M2 = '';
                           my ($I, $A, $b, $B) = @{delete $TOKENS{$token}};
                           return unless $I && $A && $b && $B;
                           my $s = $USERS{$I}->{salt};
                           my $v = $USERS{$I}->{verifier};
                           return unless $s && $v;
                           my $srv = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
                           $srv->server_init($I, $v, $s, $A, $B, $b);
                           return unless $srv->server_verify_M1($M1);
                           $M2 = $srv->server_compute_M2;
                           my $K = $srv->get_secret_K; # shared secret

 #  response[2] from server:  <--- ($M2) <---

 ###CLIENT###
 my $K;
 if ($M2 && $cli->client_verify_M2($M2)) {
   $K = $srv->get_secret_K; # shared secret
   print "Success";
 }
 else {
   print "Error";
 }

=head1 DESCRIPTION

More info about SRP protocol:

=over

=item * L<http://srp.stanford.edu/design.html>

=item * L<http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol>

=item * L<http://tools.ietf.org/html/rfc5054>

=back

This module implements SRP version 6a.

B<IMPORTANT:> This module performs some big integer arithmetics via L<Math::BigInt>.
From performance reasons it is recommended to install L<Math::BigInt::GMP>.

B<IMPORTANT:> This module needs some cryptographically strong random number generator.
It tries to use one of the following:

=over

=item * L<Crypt::OpenSSL::Random> - random_bytes()

=item * L<Net::SSLeay> - RAND_bytes()

=item * L<Crypt::Random> - makerandom_octet()

=item * L<Bytes::Random::Secure> - random_bytes()

=item * As an B<unsecure> fallback it uses buil-in rand()

=back

=head1 METHODS

=over

=item * new

 my $srp = Crypt::SRP->new($group, $hash);
 # $group ... 'RFC5054-1024bit' or 'RFC5054-1536bit' or 'RFC5054-2048bit' or
 #            'RFC5054-3072bit' or 'RFC5054-4096bit' or 'RFC5054-6144bit' or
 #            'RFC5054-8192bit'
 # $hash  ... 'SHA1' or 'SHA256' or 'SHA384' or 'SHA512'

=item * client_init

 $srp->client_init($I, $P, $s);

=item * client_compute_A

 my $A = $srp->client_compute_A();
 #or
 my ($A, $a) = $srp->client_compute_A();

=item * client_compute_M1

 my $M1 = $srp->client_compute_M1($B)

=item * client_verify_M2

 my $valid = $srp->client_verify_M2($M2);

=item * compute_verifier

 my $v = $srp->compute_verifier($I, $P, $s)

=item * compute_verifier_and_salt

 my ($s, $v) = $srp->compute_verifier_and_salt($I, $P);
 #or
 my ($s, $v) = $srp->compute_verifier_and_salt($I, $P, $s_len)

=item * server_init

 $srp->server_init($I, $v, $s);
 #or
 $srp->server_init($I, $v, $s, $A, $B, $b);

=item * server_compute_B

 my $B = $srp->server_compute_B();
 #or
 my ($B, $b) = $srp->server_compute_B();

=item * server_verify_M1

 my $valid = $srp->server_verify_M1($M1);

=item * server_compute_M2

 my $M2 = $srp->server_compute_M2();

=item * get_secret_S

 my $S = $srp->get_secret_S();

=item * get_secret_K

 my $K = $srp->get_secret_K();

=item * random_bytes

 my $rand = $srp->random_bytes();
 #or
 my $rand = $srp->random_bytes($len);

=back

=head1 COPYRIGHT

Copyright (c) 2013 DCIT, a.s. L<http://www.dcit.cz> / Karel Miko
