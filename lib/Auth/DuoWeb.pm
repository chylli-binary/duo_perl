package Auth::DuoWeb;

use strict;
use 5.008_005;
our $VERSION = '0.01';

use MIME::Base64;
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);

my $DUO_PREFIX  = 'TX';
my $APP_PREFIX  = 'APP';
my $AUTH_PREFIX = 'AUTH';

my $DUO_EXPIRE = 300;
my $APP_EXPIRE = 3600;

my $IKEY_LEN = 20;
my $SKEY_LEN = 40;
my $AKEY_LEN = 40;

our $ERR_USER = 'ERR|The username passed to sign_request() is invalid.';
our $ERR_IKEY = 'ERR|The Duo integration key passed to sign_request() is invalid.';
our $ERR_SKEY = 'ERR|The Duo secret key passed to sign_request() is invalid.';
our $ERR_AKEY = "ERR|The application secret key passed to sign_request() must be at least $AKEY_LEN characters.";
our $ERR_UNKNOWN = 'ERR|An unknown error has occurred.';


sub _sign_vals {
    my ($key, $vals, $prefix, $expire) = @_;

    my $exp = time + $expire;

    my $val = join '|', @{$vals}, $exp;
    my $b64 =encode_base64($val, '');
    my $cookie = "$prefix|$b64";

    my $sig = hmac_sha1_hex($cookie, $key);

    return "$cookie|$sig";
}


sub _parse_vals {
    my ($key, $val, $prefix) = @_;

    my $ts = time;
    my ($u_prefix, $u_b64, $u_sig) = split /\|/, $val;

    my $sig = hmac_sha1_hex("$u_prefix|$u_b64", $key);

    if (hmac_sha1_hex($sig, $key) ne hmac_sha1_hex($u_sig, $key)) {
        return '';
    }

    if ($u_prefix ne $prefix) {
        return '';
    }

    my ($user, $ikey, $exp) = split /\|/, decode_base64($u_b64);

    if ($ts >= $exp) {
        return '';
    }

    return $user;
}

sub sign_request {
    my ($ikey, $skey, $akey, $username) = @_;

    if (not $username) {
        return $ERR_USER;
    }

    if (not $ikey or length $ikey != $IKEY_LEN) {
        return $ERR_IKEY;
    }

    if (not $skey or length $skey != $SKEY_LEN) {
        return $ERR_SKEY;
    }

    if (not $akey or length $akey < $AKEY_LEN) {
        return $ERR_AKEY;
    }

    my $vals = [ $username, $ikey ];

    my $duo_sig = _sign_vals($skey, $vals, $DUO_PREFIX, $DUO_EXPIRE);
    my $app_sig = _sign_vals($akey, $vals, $APP_PREFIX, $APP_EXPIRE);

    if (not $duo_sig or not $app_sig) {
        return $ERR_UNKNOWN;
    }

    return "$duo_sig:$app_sig";
}

sub verify_response {
    my ($ikey, $skey, $akey, $sig_response) = @_;

    my ($auth_sig, $app_sig) = split /:/, $sig_response;
    my $auth_user = _parse_vals($skey, $auth_sig, $AUTH_PREFIX);
    my $app_user  = _parse_vals($akey, $app_sig, $APP_PREFIX);

    if ($auth_user ne $app_user) {
        return '';
    }

    return $auth_user;
}

1;
__END__

=encoding utf-8

=head1 NAME

Auth::DuoWeb - Duo two-factor authentication for Perl web applications

=head1 SYNOPSIS

    use Auth::DuoWeb;

    my $sig_request = Auth::DuoWeb::sign_request(
        $IKEY, $SKEY, $AKEY, $email,
    );

    my $email = Auth::DuoWeb::verify_response(
        $IKEY, $SKEY, $AKEY, param('sig_response'),
    );

=head1 DESCRIPTION

This package allows a web developer to quickly add Duo's interactive, self-service, two-factor authentication to any web login form - without setting up secondary user accounts, directory synchronization, servers, or hardware.

What's here:

js - Duo Javascript library, to be hosted by your webserver.
DuoWeb.pm - Duo Perl SDK to be integrated with your web application
t/duoweb.t - Unit tests for our SDK

=head2 sign_request

Generate a signed request for Duo authentication.
The returned value should be passed into the Duo.init() call!
in the rendered web page used for Duo authentication.

Arguments:

    ikey      -- Duo integration key
    skey      -- Duo secret key
    akey      -- Application secret key
    username  -- Primary-authenticated username

=head2 verify_response

Validate the signed response returned from Duo.

Returns the username of the authenticated user, or '' (empty
string) if secondary authentication was denied.

Arguments:

    ikey          -- Duo integration key
    skey          -- Duo secret key
    akey          -- Application secret key
    sig_response  -- The signed response POST'ed to the server

=head1 USAGE

Developer documentation: L<http://www.duosecurity.com/docs/duoweb>

=head1 Support

Report any bugs, feature requests, etc. to us directly: support@duosecurity.com

Have fun!