use strict;
use warnings;

use Crypt::SRP;
use Test::More;

sub SRP_handshake {
  my %args = @_;

  my $group   = $args{group};   # e.g. 'RFC5054-1024bit';
  my $hash    = $args{hash};    # e.g. 'SHA1';
  my $Bytes_I = $args{Bytes_I}; # e.g. 'alice';
  my $Bytes_P = $args{Bytes_P}; # e.g. 'password123';

  # optionally predefined random variables (handy for test vectors)
  my $Bytes_s = $args{Bytes_s}; # e.g. pack('H*', 'BEB25379D1A8581EB5A727673A2441EE');
  my $Hex_a   = $args{Hex_a};   # e.g. '60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393';
  my $Hex_b   = $args{Hex_b};   # e.g. 'E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20';
  
  my $Bytes_v;
  
  if ($Bytes_s) {
    $Bytes_v = Crypt::SRP->new($group, $hash)->compute_verifier($Bytes_I, $Bytes_P, $Bytes_s); 
  }
  else {
    ($Bytes_s, $Bytes_v) = Crypt::SRP->new($group, $hash)->compute_verifier_and_salt($Bytes_I, $Bytes_P); 
  }

  ###CLIENT:                                              
  my $client = Crypt::SRP->new($group, $hash);
  $client->{predefined_a} = Math::BigInt->from_hex($Hex_a) if defined $Hex_a;
  my ($Bytes_A, $Bytes_a) = $client->client_compute_A;

  # client -[$Bytes_I, $Bytes_A]---> server #
                                                          
  ###SERVER:
  my $server1 = Crypt::SRP->new($group, $hash);
  $server1->server_init($Bytes_I, $Bytes_v, $Bytes_s);
  $server1->{predefined_b} = Math::BigInt->from_hex($Hex_b) if defined $Hex_b;
  my ($Bytes_B, $Bytes_b) = $server1->server_compute_B();

  # client <---[$Bytes_B, $Bytes_s]- server #

  ###CLIENT:                                              
  $client->client_init($Bytes_I, $Bytes_P, $Bytes_s, $Bytes_B);
  my $Bytes_M1 = $client->client_compute_M1();

  # client -[$Bytes_M1]--> server #

  ###SERVER:
  my $server2 = Crypt::SRP->new($group, $hash);
  $server2->server_init($Bytes_I, $Bytes_v, $Bytes_s, $Bytes_A, $Bytes_B, $Bytes_b);
  $server2->server_verify_M1($Bytes_M1) or die "FATAL: M1 mismatch";
  my $Bytes_M2 = $server2->server_compute_M2;

  # client <--[$Bytes_M2]- server #

  ###CLIENT:
  $client->client_verify_M2($Bytes_M2) or die "FATAL: M2 mismatch";

  ###CLIENT/SERVER on both sides
  die "FATAL: K mismatch" unless $client->get_secret_K eq $server2->get_secret_K;
  my $Bytes_K = $server2->get_secret_K;

  my %result = (
        N  => { bytes=> Crypt::SRP::_bignum2bytes($server2->{Num_N}) },
        g  => { bytes=> Crypt::SRP::_bignum2bytes($server2->{Num_g}) },
        I  => { bytes=> $client->{Bytes_I} },
        P  => { bytes=> $client->{Bytes_P} },
        s  => { bytes=> $client->{Bytes_s} },
        k  => { bytes=> Crypt::SRP::_bignum2bytes($server1->{Num_k}) },
        x  => { bytes=> Crypt::SRP::_bignum2bytes($client->{Num_x}) },
        v  => { bytes=> Crypt::SRP::_bignum2bytes($server1->{Num_v}) },
        a  => { bytes=> Crypt::SRP::_bignum2bytes($client->{Num_a}) },
        b  => { bytes=> Crypt::SRP::_bignum2bytes($server1->{Num_b}) },
        A  => { bytes=> $Bytes_A },
        B  => { bytes=> $Bytes_B },
        u  => { bytes=> Crypt::SRP::_bignum2bytes($server2->{Num_u}) },
        M1 => { bytes=> $Bytes_M1 },
        M2 => { bytes=> $Bytes_M2 },
        S  => { bytes=> $server2->get_secret_S },
        K  => { bytes=> $server2->get_secret_K },
  );

  return \%result;
}

### main - test vector from http://tools.ietf.org/html/rfc5054#appendix-B

my $srp_data = SRP_handshake(
        group   => 'RFC5054-1024bit',
        hash    => 'SHA1',
        Bytes_I => "alice",
        Bytes_P => "password123",
        Bytes_s => pack('H*', 'BEB25379D1A8581EB5A727673A2441EE'),
        Hex_a   => '60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393',
        Hex_b   => 'E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20',
      );

is($srp_data->{N}->{bytes},  pack('H*', 'eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576'.
                                        'd674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad1'.
                                        '5dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec'.
                                        '68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3'), 'test N');
is($srp_data->{g}->{bytes},  pack('H*', '02'), 'test g');
is($srp_data->{I}->{bytes}, 'alice', 'test I');
is($srp_data->{P}->{bytes}, 'password123', 'test P');
is($srp_data->{s}->{bytes},  pack('H*', 'beb25379d1a8581eb5a727673a2441ee'), 'test s');

is($srp_data->{k}->{bytes},  pack('H*', '7556aa045aef2cdd07abaf0f665c3e818913186f'), 'test k');
is($srp_data->{x}->{bytes},  pack('H*', '94b7555aabe9127cc58ccf4993db6cf84d16c124'), 'test x');
is($srp_data->{v}->{bytes},  pack('H*', '7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1'.
                                        '822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a'.
                                        '48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04'.
                                        'e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb'), 'test v');
is($srp_data->{a}->{bytes},  pack('H*', '60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393'), 'test a');
is($srp_data->{b}->{bytes},  pack('H*', 'e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20'), 'test b');
is($srp_data->{A}->{bytes},  pack('H*', '61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e890'.
                                        '3211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e'.
                                        '42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261'.
                                        'eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b'), 'test A');
is($srp_data->{B}->{bytes},  pack('H*', 'bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964'.
                                        'dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610'.
                                        'd0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a'.
                                        '00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58'), 'test B');
is($srp_data->{u}->{bytes},  pack('H*', 'ce38b9593487da98554ed47d70a7ae5f462ef019'), 'test u');
is($srp_data->{M1}->{bytes}, pack('H*', '62c71b289cb22a034b405667e1541202ce5d8e03'), 'test M1');
is($srp_data->{M2}->{bytes}, pack('H*', 'b475d7f2d75ce9537748005483e5d326048b59e9'), 'test M2');
is($srp_data->{S}->{bytes},  pack('H*', 'b0dc82babcf30674ae450c0287745e7990a3381f63b387aaf271a10d233861e3'.
                                        '59b48220f7c4693c9ae12b0a6f67809f0876e2d013800d6c41bb59b6d5979b5c'.
                                        '00a172b4a2a5903a0bdcaf8a709585eb2afafa8f3499b200210dcc1f10eb3394'.
                                        '3cd67fc88a2f39a4be5bec4ec0a3212dc346d7e474b29ede8a469ffeca686e5a'), 'test S');

#K is not a part of test vector from http://tools.ietf.org/html/rfc5054#appendix-B
is($srp_data->{K}->{bytes},  pack('H*', '017eefa1cefc5c2e626e21598987f31e0f1b11bb'), 'test K');

done_testing();
