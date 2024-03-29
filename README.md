# NAME

Crypt::SRP - Secure Remote Protocol (SRP6a)

# SYNOPSIS

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
      my $K = $cli->get_secret_K; # shared secret
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

Working sample implementation of SRP authentication on client and server side is available in `examples`
subdirectory:
[srp\_server.pl](https://metacpan.org/source/MIK/Crypt-SRP-0.015/examples/srp_server.pl),
[srp\_client.pl](https://metacpan.org/source/MIK/Crypt-SRP-0.015/examples/srp_client.pl).

# DESCRIPTION

More info about SRP protocol:

- [http://srp.stanford.edu/design.html](http://srp.stanford.edu/design.html)
- [https://en.wikipedia.org/wiki/Secure\_Remote\_Password\_protocol](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)
- [https://tools.ietf.org/html/rfc2945](https://tools.ietf.org/html/rfc2945)
- [https://tools.ietf.org/html/rfc5054](https://tools.ietf.org/html/rfc5054)

This module implements SRP version 6a.

# METHODS

Login and password ($I, $P) can be ASCII strings (without utf8 flag) or raw octets. If you want special
characters in login and/or password then you have to encode them from Perl's internal from like this:
`$I = encode('utf8', $I)` or `$P = encode('utf8', $P)`

All SRP related variables ($s, $v, $A, $a, $B, $b, $M1, $M2, $S, $K) are by defaults raw octets (no BigInts, no strings
with utf8 flag). However if you set new's optional parameter `$format` to `'hex'`, `'base64'` or `'base64url'` SRP
related input parameters (not `$I` or `$P`) are expected in given encoding and return values are converted into
the same encoding as well.

- new

        my $srp = Crypt::SRP->new();

        #or
        my $srp = Crypt::SRP->new({ group => $group, hash => $hash, format => $format });
        # group       - DEFAULT='RFC5054-2048bit'
        #               'RFC5054-1024bit' or 'RFC5054-1536bit' or 'RFC5054-2048bit' or
        #               'RFC5054-3072bit' or 'RFC5054-4096bit' or 'RFC5054-6144bit' or
        #               'RFC5054-8192bit' see rfc5054 (appendix A)
        # hash        - DEFAULT='SHA256'
        #               'SHA1' or 'SHA256' or 'SHA384' or 'SHA512'
        # format      - DEFAULT='raw'
        #               'raw' or 'hex' or 'base64' or 'base64url'
        # interleaved - DEFAULT=0
        #               indicates whether the final shared secret K will be computed
        #               as SHAx(S) or SHAx_Interleaved(S) see rfc2945 (3.1 Interleaved SHA)
        # saltlen     - DEFAULT=32
        #               default length (in bytes) for generated salt
        # srptools    - DEFAULT=0 (since v0.018)
        #               operate in a mode compatible with python package srptools
        # appletv     - DEFAULT=0 (since v0.018)
        #               operate in a mode compatible with SRP6a used by AppleTV / AirPlayAuth

        #or (OLD interface)
        my $srp = Crypt::SRP->new($group, $hash, $format, $interleaved, $default_salt_len);

- reset

        $srp->reset();
        #or
        $srp->reset({ group => $group, hash => $hash, format => $format });    # see new()
        #or
        $srp->reset($group, $hash, $format, $interleaved, $default_salt_len);  # see new()

        # returns $srp (itself)

- dump

        my $serialized_state = $srp->dump();

- load

        $srp->load($serialized_state);

- compute\_verifier

        my $v = $srp->compute_verifier($I, $P, $s);

- compute\_verifier\_and\_salt

        my ($v, $s) = $srp->compute_verifier_and_salt($I, $P);
        #or
        my ($v, $s) = $srp->compute_verifier_and_salt($I, $P, $s_len);

- client\_init

        $srp->client_init($I, $P, $s, $B);

        # returns $srp (itself)

- client\_compute\_A

        my ($A, $a) = $srp->client_compute_A();
        #or
        my ($A, $a) = $srp->client_compute_A($a_len);

- client\_compute\_M1

        my $M1 = $srp->client_compute_M1($B);

- client\_verify\_M2

        my $valid = $srp->client_verify_M2($M2);

- client\_verify\_B

        my $valid = client_verify_B($B);

- server\_init

        $srp->server_init($I, $v, $s);
        #or
        $srp->server_init($I, $v, $s, $A, $B, $b);
        # returns $srp (itself)

- server\_compute\_B

        my ($B, $b) = $srp->server_compute_B();
        #or
        my ($B, $b) = $srp->server_compute_B($b_len);

- server\_fake\_B\_s

        my ($B, $s) = $srp->server_fake_B_s($I);
        #or
        my ($B, $s) = $srp->server_fake_B_s($I, $nonce);
        #or
        my ($B, $s) = $srp->server_fake_B_s($I, $nonce, $s_len);

- server\_verify\_M1

        my $valid = $srp->server_verify_M1($M1);

- server\_compute\_M2

        my $M2 = $srp->server_compute_M2();

- server\_verify\_A

        my $valid = server_verify_A($A);

- get\_secret\_S

        my $S = $srp->get_secret_S();
        #or
        my $S = $srp->get_secret_S($format);
        # $format can me 'raw' or 'hex' or 'base64' or 'base64url'

- get\_secret\_K

        my $K = $srp->get_secret_K();
        #or
        my $K = $srp->get_secret_K($format);
        # $format can me 'raw' or 'hex' or 'base64' or 'base64url'

- random\_bytes

        my $rand = $srp->random_bytes();  # $rand formated according to $format passed to new()
        #or
        my $rand = $srp->random_bytes($len);

        my $rand = Crypt::SRP->random_bytes();  # $rand always raw bytes
        #or
        my $rand = Crypt::SRP->random_bytes($len);

# LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

# COPYRIGHT

Copyright (c) 2012+ DCIT, a.s. [https://www.dcit.cz](https://www.dcit.cz) / Karel Miko
