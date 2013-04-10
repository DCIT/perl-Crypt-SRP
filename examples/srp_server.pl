#!/usr/bin/perl

# Copyright (c) 2013 DCIT, a.s. [http://www.dcit.cz] - Miko

use strict;
use warnings;
use Mojolicious::Lite;
use Crypt::SRP;

my %USERS;  # sort of "user database"
my %TOKENS; # sort of temporary "token database"
my $fmt = 'hex'; # all SRP related parameters are automatically converted from/to hex
my $dump;

%USERS = (
  alice => { # password P = "password123"
    salt     => 'beb25379d1a8581eb5a727673a2441ee',
    verifier => '7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1'.
                '822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a'.
                '48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04'.
                'e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb',
  }
);

my $cli = Crypt::SRP->new('RFC5054-1024bit', 'SHA1', 0, $fmt);
for (1..3) {
  my $I = "user$_";
  my $P = "secret$_";
  my ($s, $v) = $cli->compute_verifier_and_salt($I, $P, 32);
  $USERS{$I} = { salt=>$s, verifier=>$v };
}
for (sort keys %USERS) {
  warn "[$_] s=$USERS{$_}{salt} v=", substr($USERS{$_}{verifier},0,10), "..\n";
}
  
post '/auth/srp_step1' => sub {
    my $self = shift;
    my $I = $self->req->json->{I};
    my $A = $self->req->json->{A};
    return $self->render_json({status=>'invalid'}) unless $I && $A;
    my $srv = Crypt::SRP->new('RFC5054-1024bit', 'SHA1', 0, $fmt);
    return $self->render_json({status=>'invalid'}) unless $srv->server_verify_A($A);
    my $token = $srv->random_bytes(8);
    if ($USERS{$I} && $USERS{$I}->{salt} && $USERS{$I}->{verifier}) {
      # user exists
      my ($s, $v) = ($USERS{$I}->{salt}, $USERS{$I}->{verifier});
      $srv->server_init($I, $v, $s);
      #$srv->{predefined_b} = Math::BigInt->from_hex('E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20'); #DEBUG-ONLY
      my ($B, $b) = $srv->server_compute_B(32);
      warn "I = $I\n";
      warn "v = ", substr($v,0,30), "..\n";
      warn "B = ", substr($B,0,30), "..\n";
      warn "b = ", substr($b,0,30), "..\n";
      $TOKENS{$token} = $srv->dump;
      warn "storing state len=", length($TOKENS{$token}), "\n";
      return $self->render_json({B=>$B, s=>$s, token=>$token});
    }
    else {
      # fake response for no-nexisting user
      $dump = undef;
      my ($B, $s) = $srv->server_fake_B_s($I);
      return $self->render_json({B=>$B, s=>$s, token=>$token});
    }
  };

post '/auth/srp_step2' => sub {
    my $self = shift;
    my $M1 = $self->req->json->{M1};
    my $token = $self->req->json->{token};
    warn "token = $token\n";
    warn "M1 = $M1\n";
    return $self->render_json({status=>'error'}) unless $M1 && $token && $TOKENS{$token};
    
    my $srv = Crypt::SRP->new->load($TOKENS{$token}); #restore state

    $srv->server_verify_M1($M1) or warn "server_verify_M1 FAILED!\n" and return $self->render_json({status=>'error'});
    my $M2 = $srv->server_compute_M2($fmt);
    my $K = $srv->get_secret_K($fmt);
    warn "M2 = $M2\n";
    warn "[SUCCESS] K = $K\n";
    return $self->render_json({M2=>$M2});
  };

app->start;
