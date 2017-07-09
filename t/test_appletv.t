use strict;
use warnings;

use Crypt::SRP;
use Test::More tests => 1;

my $Bytes_I  = '0x366B4165DD64AD3A';
my $Bytes_P  = '1234';
my $Bytes_s  = pack('H*', 'd62c98fe76c77ad445828c33063fc36f');
my $Bytes_B  = pack('H*', '4223ddb35967419ddfece40d6b552b797140129c1c262da1b83d413a7f9674aff834171336dabadf9faa95962331e44838d5f66c46649d583ee44827755651215dcd5881056f7fd7d6445b844ccc5793cc3bbd5887029a5abef8b173a3ad8f81326435e9d49818275734ef483b2541f4e2b99b838164ad5fe4a7cae40599fa41bd0e72cb5495bdd5189805da44b7df9b7ed29af326bb526725c2b1f4115f9d91e41638876eeb1db26ef6aed5373f72e3907cc72997ee9132a0dcafda24115730c9db904acbed6d81dc4b02200a5f5281bf321d5a3216a709191ce6ad36d383e79be76e37a2ed7082007c51717e099e7bedd7387c3f82a916d6aca2eb2b6ff3f3');
my $Bytes_A  = pack('H*', '47662731cbe1ba0b130dc5e65320dc2a4b60371e086212a7a55ed4a3653b2d1e861569309c97b4f88433564bd47f6de13ecc440db26998478b266eaa8195a81c28f89a989bc538c477be302fd96bb3fa809e9a94b0aac28d6a00aa057892ba26b2b2cad4d8ec6a9e4207754926c985c393feb6e8b7fb82bd8043709866d7b53a592a940d8e44a7d08fbbda51bf5c9091c251988236147364cb75ad5a4efbeed242fd78496f0cda365965255c8214bd264c259fa2f2a8bfec70eecb32d2ded4c5c35e5e802a22bf58f7cd629fb2f3b4a2498b95f63eab37be9fb0f75c3fcbea8c083d0311302ebc2c3bc0a0525ba5bf3fcffe5b5668b4905a8e6cdb70d89f4b1b');
my $Bytes_a  = pack('H*', 'a18b940d3e1302e932a64defccf560a0714b3fa2683bbe3cea808b3abfa58b7d');

my $client = Crypt::SRP->new({ group => 'RFC5054-2048bit', hash => 'SHA1', format => 'raw', appletv => 1 });
$client->client_init($Bytes_I, $Bytes_P, $Bytes_s, $Bytes_B, $Bytes_A, $Bytes_a);

my $Bytes_M1 = $client->client_compute_M1();

is(unpack('H*', $Bytes_M1), '4b4e638bf08526e4229fd079675fedfd329b97ef', 'test M1');
