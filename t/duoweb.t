use strict;
use warnings;
use Auth::DuoWeb;
use Test::More;

my $IKEY = "DIXXXXXXXXXXXXXXXXXX";
my $SKEY = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
my $AKEY = "useacustomerprovidedapplicationsecretkey";
my $USER = "testuser";

my $INVALID_RESPONSE = "AUTH|INVALID|SIG";
my $EXPIRED_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|cb8f4d60ec7c261394cd5ee5a17e46ca7440d702";
my $FUTURE_RESPONSE  = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0Mw==|d20ad0d1e62d84b00a3e74ec201a5917e77b6aef";

isnt(Auth::DuoWeb::sign_request($IKEY, $SKEY, $AKEY, $USER), '', 'sign_request - Valid sign_request');
is(Auth::DuoWeb::sign_request($IKEY,     $SKEY,     $AKEY, ''),    $Auth::DuoWeb::ERR_USER, 'sign_request - Invalid user');
is(Auth::DuoWeb::sign_request('invalid', $SKEY,     $AKEY, $USER), $Auth::DuoWeb::ERR_IKEY, 'sign_request - Invalid integration key');
is(Auth::DuoWeb::sign_request($IKEY,     'invalid', $AKEY, $USER), $Auth::DuoWeb::ERR_SKEY, 'sign_request - Invalid secret key');
is(Auth::DuoWeb::sign_request($IKEY, $SKEY, 'invalid', $USER), $Auth::DuoWeb::ERR_AKEY, 'sign_request - Invalid application key');

my (undef, $valid_app_sig)   = split /:/, Auth::DuoWeb::sign_request($IKEY, $SKEY, $AKEY,         $USER);
my (undef, $invalid_app_sig) = split /:/, Auth::DuoWeb::sign_request($IKEY, $SKEY, 'invalid' x 6, $USER);

is(Auth::DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $INVALID_RESPONSE . ':' . $valid_app_sig), '', 'verify_response - Invalid user');
is(Auth::DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $EXPIRED_RESPONSE . ':' . $valid_app_sig), '', 'verify_response - Expired user');
is(Auth::DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $invalid_app_sig),
    '', 'verify_response - Future user, invalid app sig');
is(Auth::DuoWeb::verify_response($IKEY, $SKEY, $AKEY, $FUTURE_RESPONSE . ':' . $valid_app_sig), $USER, 'verify_response - Future user');

done_testing();

