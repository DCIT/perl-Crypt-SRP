# Copyright (c) 2013 DCIT, a.s. [http://www.dcit.cz] - Miko

use strict;
use warnings;
use Mojolicious::Lite;
use Mojo::Util qw(b64_encode b64_decode);
use Crypt::SRP;
use Digest::SHA qw(hmac_sha256);

my %USERS;  # sort of "user database"
my %TOKENS; # sort of temporary "token database"

%USERS = (
  alice => { # password P = "password123"
    salt     => pack('H*', 'BEB25379D1A8581EB5A727673A2441EE'),
    verifier => pack('H*', '7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1'.
                           '822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a'.
                           '48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04'.
                           'e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb'),
  }
);

my $cli = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
for (1..3) {
  my $I = "user$_";
  my $P = "secret$_";
  my ($s, $v) = $cli->compute_verifier_and_salt($I, $P);
  $USERS{$I} = { salt=>$s, verifier=>$v };
}

post '/auth/srp_step1' => sub {
    my $self = shift;
    my $I = b64_decode $self->req->json->{I};
    my $A = b64_decode $self->req->json->{A};
    return $self->render_json({status=>'invalid'}) unless $I && $A;
    my $srv = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
    return $self->render_json({status=>'invalid'}) unless $srv->validate_A_or_B($A);
    if ($USERS{$I} && $USERS{$I}->{salt} && $USERS{$I}->{verifier}) {
      # user exists
      my ($s, $v) = ($USERS{$I}->{salt}, $USERS{$I}->{verifier});
      $srv->server_init($I, $v, $s);
      my ($B, $b) = $srv->server_compute_B(32);
      warn "I = $I\n";
      warn "v = ", unpack("H*", substr($v,0,16)), "... len=", length($v), "\n";
      warn "B = ", unpack("H*", substr($B,0,16)), "... len=", length($B), "\n";
      warn "b = ", unpack("H*", substr($b,0,16)), "... len=", length($b), "\n";
      my $token = $srv->random_bytes(32);
      $TOKENS{$token} = [$I, $A, $B, $b];
      return $self->render_json({B=>b64_encode($B), s=>b64_encode($s), token=>b64_encode($token)});
    }
    else {
      # fake response for no-nexisting user
      my $token = $srv->random_bytes(32);
      my $B = $srv->random_bytes(128); #XXX-FIXME this is not a good idea
      my $s = hmac_sha256($I, 'fixed nonsense');
      return $self->render_json({B=>$B, s=>$s, token=>$token});
    }
  };

post '/auth/srp_step2' => sub {
    my $self = shift;
    my $M1 = b64_decode $self->req->json->{M1};
    my $token = b64_decode $self->req->json->{token};
    return $self->render_json({status=>'error'}) unless $M1 && $token && $TOKENS{$token};
    my $M2 = '';
    my ($I, $A, $B, $b) = @{delete $TOKENS{$token}};
    return $self->render_json({status=>'error'}) unless $I && $A && $B && $b && $USERS{$I};
    my ($s, $v) = ($USERS{$I}->{salt}, $USERS{$I}->{verifier});
    return unless $s && $v;
    my $srv = Crypt::SRP->new('RFC5054-1024bit', 'SHA1');
    $srv->server_init($I, $v, $s, $A, $B, $b);
    return $self->render_json({status=>'error'}) unless $srv->server_verify_M1($M1);
    $M2 = $srv->server_compute_M2;
    return $self->render_json({M2=>b64_encode($M2)});
  };

app->start;
