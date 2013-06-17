package Crypt::SRP;

# Copyright (c) 2012 DCIT, a.s. [http://www.dcit.cz] - Miko

use strict;
use warnings;

our $VERSION = '0.010';
$VERSION = eval $VERSION;
#BEWARE update also version in URLs mentioned in documentation below

use Math::BigInt try => 'GMP';
use Digest::SHA;
use MIME::Base64 qw(encode_base64 decode_base64);
use Config;
use Storable qw(nfreeze thaw);

use constant _state_vars  => [ qw(Bytes_I Bytes_K Bytes_M1 Bytes_M2 Bytes_P Bytes_s Num_a Num_A Num_b Num_B Num_k Num_S Num_u Num_v Num_x) ];
use constant _static_vars => [ qw(HASH INTERLEAVED GROUP FORMAT SALT_LEN) ];

### predefined parameters - see http://tools.ietf.org/html/rfc5054 appendix A

use constant _predefined_groups => {
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
  my ($class, $group, $hash, $format, $interleaved, $default_salt_len) = @_;
  my $self = bless {}, $class;

  $self->{GROUP} = $group || 'RFC5054-2048bit';
  $self->{HASH} = $hash || 'SHA256';
  $self->{FORMAT} = $format || 'raw';
  $self->{INTERLEAVED} = $interleaved || 0;
  $self->{SALT_LEN} = $default_salt_len || 32;

  $self->_initialize();
  return $self;
}

### class PUBLIC methods

sub reset {
  my ($self, $group, $hash, $format, $interleaved, $default_salt_len) = @_;

  $self->{GROUP} = $group if defined $group;
  $self->{HASH} = $hash if defined $hash;
  $self->{FORMAT} = $format if defined $format;
  $self->{INTERLEAVED} = $interleaved if defined $interleaved;
  $self->{SALT_LEN} = $default_salt_len if defined $default_salt_len;

  delete $self->{$_} for (@{_state_vars()});

  $self->_initialize();
  return $self;
}

sub dump {
  my $self = shift;
  my $state = [ map {$self->{$_}} (@{_state_vars()}, @{_static_vars()}) ];
  return encode_base64(nfreeze($state), "");
}

sub load {
  my ($self, $state) = @_;
  $self->reset;
  my $s = thaw(decode_base64($state));
  my @list = (@{_state_vars()}, @{_static_vars()});
  $self->{$list[$_]} = $s->[$_] for 0..$#list;
  $self->_initialize();
  return $self;
}

sub client_init {
  my ($self, $Bytes_I, $Bytes_P, $Bytes_s, $Bytes_B, $Bytes_A, $Bytes_a) = @_;
  # do not unformat $Bytes_I, $Bytes_P
  $self->{Bytes_I} = $Bytes_I;
  $self->{Bytes_P} = $Bytes_P;
  $self->{Bytes_s} = $self->_unformat($Bytes_s);
  $self->{Num_x}   = $self->_calc_x();            # x = HASH(s | HASH(I | ":" | P))
  #optional params
  $self->{Num_B}   = _bytes2bignum($self->_unformat($Bytes_B)) if defined $Bytes_B;
  $self->{Num_A}   = _bytes2bignum($self->_unformat($Bytes_A)) if defined $Bytes_A;
  $self->{Num_a}   = _bytes2bignum($self->_unformat($Bytes_a)) if defined $Bytes_a;
  return $self;
}

sub server_init {
  my ($self, $Bytes_I, $Bytes_v, $Bytes_s, $Bytes_A, $Bytes_B, $Bytes_b) = @_;
  # do not unformat $Bytes_I
  $self->{Bytes_I} = $Bytes_I;
  $self->{Num_v}   = _bytes2bignum($self->_unformat($Bytes_v));
  $self->{Bytes_s} = $self->_unformat($Bytes_s);
  #optional params
  $self->{Num_A}   = _bytes2bignum($self->_unformat($Bytes_A)) if defined $Bytes_A;
  $self->{Num_B}   = _bytes2bignum($self->_unformat($Bytes_B)) if defined $Bytes_B;
  $self->{Num_b}   = _bytes2bignum($self->_unformat($Bytes_b)) if defined $Bytes_b;
  return $self;
}

sub client_compute_A {
  my ($self, $a_len) = @_;
  $self->{Num_a} = $self->_generate_SRP_a($a_len); # a = random() // a has min 256 bits, a < N
  $self->{Num_A} = $self->_calc_A;                 # A = g^a % N
  my $Bytes_A = _bignum2bytes($self->{Num_A});
  my $Bytes_a = _bignum2bytes($self->{Num_a});
  return ($self->_format($Bytes_A), $self->_format($Bytes_a));
}

sub client_compute_M1 {
  my ($self) = @_;
  $self->{Num_u}    = $self->_calc_u;        # u = HASH(PAD(A) | PAD(B))
  $self->{Num_k}    = $self->_calc_k;        # k = HASH(N | PAD(g))
  $self->{Num_S}    = $self->_calc_S_client; # S = (B - (k * ((g^x)%N) )) ^ (a + (u * x)) % N
  $self->{Bytes_K}  = $self->_calc_K;        # K = HASH( PAD(S) )
  $self->{Bytes_M1} = $self->_calc_M1;       # M1 = HASH( HASH(N) XOR HASH(PAD(g)) | HASH(I) | s | PAD(A) | PAD(B) | K )
  return $self->_format($self->{Bytes_M1});
}

sub client_verify_M2 {
  my ($self, $Bytes_M2) = @_;
  $Bytes_M2 = $self->_unformat($Bytes_M2);
  my $M2 = $self->_calc_M2;                  # M2 = HASH( PAD(A) | M1 | K )
  return 0 unless defined $Bytes_M2 && defined $M2 && $Bytes_M2 eq $M2;
  $self->{Bytes_M2} = $M2;
  return 1;
}

sub server_compute_B {
  my ($self, $b_len) = @_;
  $self->{Num_b} = $self->_generate_SRP_b($b_len); # b = random() // b has min 256 bits, b < N
  $self->{Num_k} = $self->_calc_k;                 # k = HASH(N | PAD(g))
  $self->{Num_B} = $self->_calc_B;                 # B = ( k*v + (g^b % N) ) % N
  my $Bytes_B = _bignum2bytes($self->{Num_B});
  my $Bytes_b = _bignum2bytes($self->{Num_b});
  return ($self->_format($Bytes_B), $self->_format($Bytes_b));
}

sub server_fake_B_s {
  my ($self, $I, $nonce, $s_len) = @_;
  return unless $I;
  $s_len ||= $self->{SALT_LEN};
  # default $nonce should be fixed for repeated invocation on the same machine (in different processes)
  $nonce ||= join(":", @INC, $Config{archname}, $Config{myuname}, $^X, $^V, $<, $(, $ENV{PATH}, $ENV{HOSTNAME}, $ENV{HOME});
  my $b = _bytes2bignum(_random_bytes(6)); #XXX maybe too short
  my $B = _bignum2bytes(Math::BigInt->new($self->{Num_g})->copy->bmodpow($b, $self->{Num_N}));
  my $s = '';
  my $i = 1;
  $s .= Digest::SHA::hmac_sha256($I, $nonce.$i++) while length($s) < $s_len;
  $s = substr($s, 0, $s_len);
  return ($self->_format($B), $self->_format($s));
}

sub server_verify_M1 {
  my ($self, $Bytes_M1) = @_;
  $Bytes_M1 = $self->_unformat($Bytes_M1);
  $self->{Num_u}   = $self->_calc_u;         # u = HASH(PAD(A) | PAD(B))
  $self->{Num_S}   = $self->_calc_S_server;  # S = ( (A * ((v^u)%N)) ^ b) % N
  $self->{Bytes_K} = $self->_calc_K;         # K = HASH( PAD(S) )
  my $M1 = $self->_calc_M1;                  # M1 = HASH( HASH(N) XOR HASH(PAD(g)) | HASH(I) | s | PAD(A) | PAD(B) | K )
  return 0 unless $Bytes_M1 eq $M1;
  $self->{Bytes_M1} = $M1;
  return 1;
}

sub server_compute_M2 {
  my ($self) = @_;
  $self->{Bytes_M2} = $self->_calc_M2;       # M2 = HASH( PAD(A) | M1 | K )
  return $self->_format($self->{Bytes_M2});
}

sub get_secret_K {
  my ($self, $format) = @_;
  return $self->_format($self->{Bytes_K}, $format);
}

sub get_secret_S {
  my ($self, $format) = @_;
  return $self->_format(_bignum2bytes($self->{Num_S}), $format);
}

sub compute_verifier {
  my ($self, $Bytes_I, $Bytes_P, $Bytes_s) = @_;
  $Bytes_s = $self->_unformat($Bytes_s);
  # do not unformat $Bytes_I, $Bytes_P
  $self->client_init($Bytes_I, $Bytes_P, $Bytes_s);
  return $self->_format($self->_calc_v);
}

sub compute_verifier_and_salt {
  my ($self, $Bytes_I, $Bytes_P, $salt_len) = @_;
  # do not unformat $Bytes_I, $Bytes_P
  $salt_len ||= $self->{SALT_LEN};
  my $Bytes_s = _random_bytes($salt_len);
  $self->client_init($Bytes_I, $Bytes_P, $self->_format($Bytes_s));
  return ($self->_format($self->_calc_v), $self->_format($Bytes_s));
}

sub server_verify_A {
  my ($self, $Bytes_A) = @_;
  $Bytes_A = $self->_unformat($Bytes_A);
  return 0 unless $self->_validate_A_or_B($Bytes_A);
  $self->{Num_A} = _bytes2bignum($Bytes_A);
  return 1;
}

sub client_verify_B {
  my ($self, $Bytes_B) = @_;
  $Bytes_B = $self->_unformat($Bytes_B);
  return 0 unless $self->_validate_A_or_B($Bytes_B);
  $self->{Num_B} = _bytes2bignum($Bytes_B);
  return 1;
}

sub random_bytes {
  my ($self, $len) = @_;
  return _random_bytes($len) unless ref $self; # Crypt::SRP->random_bytes(32);
  return $self->_format(_random_bytes($len));  # $srp->random_bytes(32);
}

### class PRIVATE methods

sub _initialize {
  my $self = shift;

  # setup N and g values
  if ($self->{GROUP} =~ /RFC5054-(1024|1536|2048|3072|4096|6144|8192)bit$/) {
    my $str = _predefined_groups->{$self->{GROUP}}->{N};
    $str =~ s/[\r\n\s]*//sg;
    $str = "0x$str" unless $str =~ /^0x/;
    $self->{Num_N} = Math::BigInt->from_hex($str);
    $self->{Num_g} = Math::BigInt->new(_predefined_groups->{$self->{GROUP}}->{g});
    $self->{N_LENGTH} = length(_bignum2bytes($self->{Num_N}));
  }
  else {
    die "FATAL: invalid group_params '$self->{GROUP}'";
  }

  # test hash function
  die "FATAL: invalid hash '$self->{HASH}'" unless defined $self->_HASH("test");
  return $self;
}

sub _HASH {
  my ($self, $data) = @_;
  #utf8::downgrade($data); #XXX-FIXME just workaround as Digest::SHA is buggy when UTF8 flag is on
  return Digest::SHA::sha1($data)   if $self->{HASH} eq 'SHA1';
  return Digest::SHA::sha256($data) if $self->{HASH} eq 'SHA256';
  return Digest::SHA::sha384($data) if $self->{HASH} eq 'SHA384';
  return Digest::SHA::sha512($data) if $self->{HASH} eq 'SHA512';
  return undef;
}

sub _HASH_Interleaved { #implemented according to http://tools.ietf.org/html/rfc2945 (3.1 Interleaved SHA)
  my ($self, $data) = @_;
  #we assume no leading zero bytes in $data
  my @all_bytes = split(//, $data);
  #if the length of the $data is odd, remove the first byte
  shift @all_bytes if @all_bytes % 2;
  my @E = map { $all_bytes[2*($_-1)] }   1 .. @all_bytes/2; # even bytes
  my @F = map { $all_bytes[2*($_-1)+1] } 1 .. @all_bytes/2; # odd bytes
  my @G = split //, $self->_HASH(@E);
  my @H = split //, $self->_HASH(@F);
  my @result;
  $result[2*$_]   = $G[$_] for 0 .. $#G;
  $result[2*$_+1] = $H[$_] for 0 .. $#H;
  return join('', @result);
}

sub _PAD {
  my ($self, $data) = @_;
  return $data if length($data) >= $self->{N_LENGTH};
  return (chr(0) x ($self->{N_LENGTH} - length($data))) . $data;
}

sub _calc_x {
  my $self = shift;
  return undef unless defined $self->{Bytes_s} && defined $self->{Bytes_I} && defined $self->{Bytes_P};
  # x = HASH(s | HASH(I | ":" | P))
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
  # u = HASH(PAD(A) | PAD(B))
  my $Bytes_u = $self->_HASH( $self->_PAD(_bignum2bytes($self->{Num_A})) . $self->_PAD(_bignum2bytes($self->{Num_B})) );
  my $Num_u = _bytes2bignum($Bytes_u);
  return $Num_u;
}

sub _calc_k {
  my $self = shift;
  return undef unless defined $self->{Num_N} && defined $self->{Num_g};
  # k = HASH(N | PAD(g))
  my $Num_k = _bytes2bignum( $self->_HASH(_bignum2bytes($self->{Num_N}) . $self->_PAD(_bignum2bytes($self->{Num_g}))) );
  return $Num_k;
}

sub _calc_S_client {
  my $self = shift;
  return undef unless defined $self->{Num_B} && defined $self->{Num_a} && defined $self->{Num_u} && defined $self->{Num_k};
  return undef unless defined $self->{Num_x} && defined $self->{Num_N} && defined $self->{Num_g};
  # S = (B - (k * ((g^x)%N) )) ^ (a + (u * x)) % N
  my $tmp1 = Math::BigInt->new($self->{Num_g})->copy->bmodpow($self->{Num_x}, $self->{Num_N})->bmul($self->{Num_k})->bmod($self->{Num_N});
  my $tmp2 = Math::BigInt->new($self->{Num_u})->copy->bmul($self->{Num_x})->badd($self->{Num_a});
  my $tmp3 = Math::BigInt->new($self->{Num_B})->copy->bsub($tmp1);
  my $Num_S = $tmp3->bmodpow($tmp2, $self->{Num_N}); #XXX this fails on Math-BigInt before 1.991
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
  my $Bytes_S = _bignum2bytes($self->{Num_S});
  # K = HASH(PAD(S))  or  K = HASH_Interleaved(PAD(S))
  my $Bytes_K = $self->{INTERLEAVED} ? $self->_HASH_Interleaved($self->_PAD($Bytes_S)) : $self->_HASH($self->_PAD($Bytes_S));
  return $Bytes_K
}

sub _calc_M1 {
  my $self = shift;
  return undef unless defined $self->{Num_A} && defined $self->{Num_B} && defined $self->{Num_N} && defined $self->{Num_g};
  return undef unless defined $self->{Bytes_K} && defined $self->{Bytes_I} && defined $self->{Bytes_s};
  # M1 = HASH( HASH(N) XOR HASH(PAD(g)) | HASH(I) | s | PAD(A) | PAD(B) | K )
  my $data1 = ($self->_HASH(_bignum2bytes($self->{Num_N})) ^ $self->_HASH($self->_PAD(_bignum2bytes($self->{Num_g})))) . $self->_HASH($self->{Bytes_I});
  my $data2 = $self->{Bytes_s} . $self->_PAD(_bignum2bytes($self->{Num_A})) . $self->_PAD(_bignum2bytes($self->{Num_B})) . $self->{Bytes_K};
  my $Bytes_M1 = $self->_HASH( $data1 . $data2 );
  return $Bytes_M1;
}

sub _calc_M2 {
  my $self = shift;
  return undef unless defined $self->{Bytes_K} && defined $self->{Num_A} && defined $self->{Bytes_M1};
  # M2 = HASH( PAD(A) | M1 | K )
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
  my ($self, $len, $pre) = @_;
  my $min = Math::BigInt->new(256)->bpow(31); # we require minimum 256bits (=32bytes)
  my $max = Math::BigInt->new($self->{Num_N})->copy->bsub(1); # $max = N-1
  if (defined $pre) {
    my $result = $pre;
    die "Invalid (too short) prefefined value" unless $result->bcmp($min) >= 0;
    die "Invalid (too big) prefefined value"   unless $result->bcmp($max) <= 0;
    return $result;
  }
  $len ||= $self->{N_LENGTH};
  return undef if $len<32;
  for(1..100) {
    my $result = _bytes2bignum($self->random_bytes($len));
    $result->bmod($max)->badd(1); # 1 <= $result <= N-1
    return $result if $result->bcmp($min) >= 0 # $min <= $result <= N-1
  }
  return undef;
}

sub _generate_SRP_a {
  my ($self, $a_len) = @_;
  $self->_generate_SRP_a_or_b($a_len, $self->{predefined_a});
}

sub _generate_SRP_b {
  my ($self, $b_len) = @_;
  $self->_generate_SRP_a_or_b($b_len, $self->{predefined_b});
}

sub _validate_A_or_B {
  my ($self, $bytes) = @_;
  return 0 unless $bytes && $self->{Num_N};
  my $num = _bytes2bignum($bytes);
  return 0 unless $num;
  return 0 if $num->bmod($self->{Num_N}) == 0; # num % N == 0
  return 1;
}

### helper functions - NOT METHODS!!!

sub _random_bytes {
  my $length = shift || 32;
  my $rv;

  if (eval {require Crypt::PRNG}) {
    $rv = Crypt::PRNG::random_bytes($length);
  }
  elsif (eval {require Crypt::OpenSSL::Random}) {
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
    $rv = Bytes::Random::Secure::random_bytes($length);
  }

  if (!defined $rv)  {
    warn "WARNING: Generating random bytes via insecure rand()\n";
    $rv = pack('C*', map(int(rand(256)), 1..$length));
  }

  return $rv;
}

sub _bignum2bytes {
  my $bignum = shift;
  return undef unless defined $bignum && ref($bignum) eq 'Math::BigInt';
  return _unhex($bignum->as_hex);
}

sub _bytes2bignum {
  my $bytes = shift;
  return undef unless defined $bytes;
  return Math::BigInt->from_hex('0x'.unpack("H*", $bytes));
}

sub _format {
  my ($self, $bytes, $format) = @_;
  $format ||= $self->{FORMAT};
  return undef                     unless defined $bytes;
  return $bytes                    if $format eq 'raw';
  return unpack("H*", $bytes)      if $format eq 'hex';
  return encode_base64($bytes, "") if $format eq 'base64';
  return _base64url_enc($bytes)    if $format eq 'base64url';
  return undef;
}

sub _unformat {
  my ($self, $input, $format) = @_;
  $format ||= $self->{FORMAT};
  return undef                  unless defined $input;
  return $input                 if $format eq 'raw';
  return _unhex($input)         if $format eq 'hex';
  return decode_base64($input)  if $format eq 'base64';
  return _base64url_dec($input) if $format eq 'base64url';
  return undef;
}

sub _unhex {
  my $hex = shift;
  $hex =~ s/^0x//;                    # strip leading '0x...'
  $hex = "0$hex" if length($hex) % 2; # add leading '0' if neccessary
  return pack("H*", $hex);  
}

# RFC 4648 Base64 URL Safe - https://tools.ietf.org/html/rfc4648#page-7
sub _base64url_enc {
    my $data = shift;
    my $b64 = encode_base64($data, '');
    $b64 =~ s/=+\z//;
    $b64 =~ tr[+/][-_];
    return $b64;
}

sub _base64url_dec {
    my $b64 = shift;
    $b64 =~ tr[-_][+/];
    $b64 .= '=' while length($b64) % 4;
    return decode_base64($b64);
}

1;

__END__

=head1 NAME

Crypt::SRP - Secure Remote Protocol (SRP6a)

=head1 SYNOPSIS

Example 1 - SRP login handshake:

 ###CLIENT###
 my $I = '...'; # login entered by user
 my $P = '...'; # password entered by user
 my $cli = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
 my ($A, $a) = $cli->client_compute_A;

 #  request[1] to server:  ---> /auth/srp_step1 ($I, $A) --->

                           ###SERVER###
                           my %USERS;  # sort of "user database"
                           my %TOKENS; # sort of temporary "token database"
                           my $v = $USERS{$I}->{verifier};
                           my $s = $USERS{$I}->{salt};
                           my $srv = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
                           return unless $srv->server_verify_A($A);
                           $srv->server_init($I, $v, $s);
                           my ($B, $b) = $srv->server_compute_B;
                           my $token = $srv->random_bytes(32);
                           $TOKENS{$token} = [$I, $A, $B, $b];

 #  response[1] from server:  <--- ($B, $s, $token) <---

 ###CLIENT###
 return unless $cli->client_verify_B($B);
 $cli->client_init($I, $P, $s);
 my $M1 = $cli->client_compute_M1;

 #  request[2] to server:  ---> /auth/srp_step2 ($M1, $token) --->

                           ###SERVER###
                           my $M2 = '';
                           return unless $M1 && $token && $TOKENS{$token};
                           my ($I, $A, $B, $b) = @{delete $TOKENS{$token}};
                           return unless $I && $A && $B && $b && $USERS{$I};
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
 if ($M2 && $cli->client_verify_M2($M2)) {
   my $K = $srv->get_secret_K; # shared secret
   print "SUCCESS";
 }
 else {
   print "ERROR";
 }

Example 2 - creating a new user and his/her password verifier:

 ###CLIENT###
 my $I = '...'; # login entered by user
 my $P = '...'; # password entered by user
 my $cli = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
 my ($v, $s) = $cli->compute_verifier_and_salt($I, $P);

 #  request to server:  ---> /auth/create_user [$I, $s, $v] --->

                           ###SERVER###
                           my %USERS;  # sort of "user database"
                           die "user already exists" unless $USERS{$I};
                           $USERS{$I}->{salt} = $s;
                           $USERS{$I}->{verifier} = $v;

Working sample implementation of SRP authentication on client and server side is available in C<examples>
subdirectory:
L<srp_server.pl|https://metacpan.org/source/MIK/Crypt-SRP-0.005/examples/srp_server.pl>,
L<srp_client.pl|https://metacpan.org/source/MIK/Crypt-SRP-0.005/examples/srp_client.pl>.

=head1 DESCRIPTION

More info about SRP protocol:

=over

=item * L<http://srp.stanford.edu/design.html>

=item * L<http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol>

=item * L<http://tools.ietf.org/html/rfc5054>

=back

This module implements SRP version 6a.

B<IMPORTANT:> This module performs some big integer arithmetic via L<Math::BigInt>.
From performance reasons it is recommended to install L<Math::BigInt::GMP>.

B<IMPORTANT:> This module needs a cryptographically strong random
number generator. It tries to use one of the following:

=over

=item * L<Crypt::PRNG> - random_bytes()

=item * L<Crypt::OpenSSL::Random> - random_bytes()

=item * L<Net::SSLeay> - RAND_bytes()

=item * L<Crypt::Random> - makerandom_octet()

=item * L<Bytes::Random::Secure> - random_bytes()

=item * As an B<unsecure> fallback it uses built-in rand()

=back

=head1 METHODS

Login and password ($I, $P) can be ASCII strings (without utf8 flag) or raw octets. If you want special
characters in login and/or password then you have to encode them from Perl's internal from like this:
C<$I = encode('utf8', $I)> or C<$P = encode('utf8', $P)>

All SRP related variables ($s, $v, $A, $a, $B, $b, $M1, $M2, $S, $K) are by defaults raw octets (no BigInts no strings
with utf8 flag). However if you set new's optional parameter C<$format> to C<'hex'>, C<'base64'> or C<'base64url'> SRP
related input parameters (not C<$I> or C<$P>) are expected in given encoding and return values are converted into
the same encoding as well.

=over

=item * new

 my $srp = Crypt::SRP->new();
 #or
 my $srp = Crypt::SRP->new($group, $hash, $format, $interleaved, $default_salt_len);
 # $group ... (optional, DEFAULT='RFC5054-2048bit')
 #            'RFC5054-1024bit' or 'RFC5054-1536bit' or 'RFC5054-2048bit' or
 #            'RFC5054-3072bit' or 'RFC5054-4096bit' or 'RFC5054-6144bit' or
 #            'RFC5054-8192bit' see rfc5054 (appendix A)
 # $hash  ... (optional, DEFAULT='SHA256')
 #            'SHA1' or 'SHA256' or 'SHA384' or 'SHA512'
 # $format ... (optional, DEFAULT='raw')
 #             'raw' or 'hex' or 'base64' or 'base64url'
 # $interleaved ... (optional, DEFAULT=0) indicates whether the final shared
 #                  secret K will be computed as SHAx(S) or SHAx_Interleaved(S)
 #                  see rfc2945 (3.1 Interleaved SHA)
 # $default_salt_len ... (optional, DEFAULT=32)
 #                        default length (in bytes) for generated salt

=item * reset

 $srp->reset();
 #or
 $srp->reset($group, $hash, $format, $interleaved, $default_salt_len);  # see new()

 # returns $srp (itself)

=item * dump

 my $serialized_state = $srp->dump();

=item * load

 $srp->load($serialized_state);

=item * compute_verifier

 my $v = $srp->compute_verifier($I, $P, $s);

=item * compute_verifier_and_salt

 my ($v, $s) = $srp->compute_verifier_and_salt($I, $P);
 #or
 my ($v, $s) = $srp->compute_verifier_and_salt($I, $P, $s_len);

=item * client_init

 $srp->client_init($I, $P, $s, $B);

 # returns $srp (itself)

=item * client_compute_A

 my ($A, $a) = $srp->client_compute_A();
 #or
 my ($A, $a) = $srp->client_compute_A($a_len);

=item * client_compute_M1

 my $M1 = $srp->client_compute_M1($B);

=item * client_verify_M2

 my $valid = $srp->client_verify_M2($M2);

=item * client_verify_B

 my $valid = client_verify_B($B);

=item * server_init

 $srp->server_init($I, $v, $s);
 #or
 $srp->server_init($I, $v, $s, $A, $B, $b);
 # returns $srp (itself)

=item * server_compute_B

 my ($B, $b) = $srp->server_compute_B();
 #or
 my ($B, $b) = $srp->server_compute_B($b_len);

=item * server_fake_B_s

 my ($B, $s) = $srp->server_fake_B_s($I);
 #or
 my ($B, $s) = $srp->server_fake_B_s($I, $nonce);
 #or
 my ($B, $s) = $srp->server_fake_B_s($I, $nonce, $s_len);

=item * server_verify_M1

 my $valid = $srp->server_verify_M1($M1);

=item * server_compute_M2

 my $M2 = $srp->server_compute_M2();

=item * server_verify_A

 my $valid = server_verify_A($A);

=item * get_secret_S

 my $S = $srp->get_secret_S();
 #or
 my $S = $srp->get_secret_S($format);
 # $format can me 'raw' or 'hex' or 'base64' or 'base64url'

=item * get_secret_K

 my $K = $srp->get_secret_K();
 #or
 my $K = $srp->get_secret_K($format);
 # $format can me 'raw' or 'hex' or 'base64' or 'base64url'

=item * random_bytes

 my $rand = $srp->random_bytes();  # $rand formated according to $format passed to new()
 #or
 my $rand = $srp->random_bytes($len);

 my $rand = Crypt::SRP->random_bytes();  # $rand always raw bytes
 #or
 my $rand = Crypt::SRP->random_bytes($len);

=back

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=head1 COPYRIGHT

Copyright (c) 2013 DCIT, a.s. L<http://www.dcit.cz> / Karel Miko
