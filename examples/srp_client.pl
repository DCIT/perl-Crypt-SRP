#!/usr/bin/perl

# Copyright (c) 2013 DCIT, a.s. [http://www.dcit.cz] - Miko

use strict;
use warnings;
use Mojo::UserAgent;
use Mojo::Util qw(b64_encode b64_decode);
use Crypt::SRP;

my $ua = Mojo::UserAgent->new;
#$ua->http_proxy('http://127.0.0.1:8081');

my $base_url = 'http://127.0.0.1:3000';

my @test_set = ( ['alice', 'password123'] );
push @test_set, ["user$_", "secret$_"] for (1..3);

for (@test_set) {
  my $I = $_->[0];
  my $P = $_->[1];

  warn "#####################\n";
  warn "# [login=$I] SRP step1\n";

  my $cli = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
  my ($A, $a) = $cli->client_compute_A(32);
  warn "I = $I\n";
  warn "P = $P\n";
  warn "A = ", unpack("H*", substr($A,0,16)), "... len=", length($A), "\n";
  warn "a = ", unpack("H*", substr($a,0,16)), "... len=", length($a), "\n";
  warn ">> gonna send request 1\n\n";
  my $tx1 = $ua->post("$base_url/auth/srp_step1" => json => {I=>b64_encode($I,''), A=>b64_encode($A,'')});
  $tx1->res->json or warn("invalid response") and next;

  warn "# [login=$I] SRP step2\n";

  my $s = b64_decode $tx1->res->json->{s};
  my $B = b64_decode $tx1->res->json->{B};  
  my $token = b64_decode $tx1->res->json->{token};
  $cli->validate_A_or_B($B) or warn("invalid B") and next;
  $cli->client_init($I, $P, $s, $B);
  my $M1 = $cli->client_compute_M1();
  warn "token = ", unpack("H*", $token), "\n";
  warn "s = ", unpack("H*", $s), "\n";
  warn "B = ", unpack("H*", substr($B,0,16)), "... len=", length($B), "\n";
  warn "M1= ", unpack("H*", $M1), "\n";
  warn ">> gonna send request 2\n\n";
  my $tx2 = $ua->post("$base_url/auth/srp_step2" => json => {M1=>b64_encode($M1,''), token=>b64_encode($token,'')});
  $tx2->res->json or warn("invalid response") and next;

  warn "# [login=$I] SRP result\n";

  my $M2 = b64_decode $tx2->res->json->{M2};
  warn "M2= ", unpack("H*", $M2), "\n" if $M2;
  if ($M2 && $cli->client_verify_M2($M2)) {
     my $K = $cli->get_secret_K; # shared secret
     warn "K = ", unpack("H*", $K), "\n";
     warn "SUCCESS\n\n";
   }
   else {
     warn "ERROR\n\n";
   }
 }