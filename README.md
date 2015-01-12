# NAME

Auth::DuoWeb - Duo two-factor authentication for Perl web applications

# SYNOPSIS

    use Auth::DuoWeb;

    my $sig_request = Auth::DuoWeb::sign_request(
        $IKEY, $SKEY, $AKEY, $email,
    );

    my $email = Auth::DuoWeb::verify_response(
        $IKEY, $SKEY, $AKEY, param('sig_response'),
    );

# DESCRIPTION

This package allows a web developer to quickly add Duo's interactive, self-service, two-factor authentication to any web login form - without setting up secondary user accounts, directory synchronization, servers, or hardware.

What's here:

js - Duo Javascript library, to be hosted by your webserver.
DuoWeb.pm - Duo Perl SDK to be integrated with your web application
t/duoweb.t - Unit tests for our SDK

## sign\_request

Generate a signed request for Duo authentication.
The returned value should be passed into the Duo.init() call!
in the rendered web page used for Duo authentication.

Arguments:

    ikey      -- Duo integration key
    skey      -- Duo secret key
    akey      -- Application secret key
    username  -- Primary-authenticated username

## verify\_response

Validate the signed response returned from Duo.

Returns the username of the authenticated user, or '' (empty
string) if secondary authentication was denied.

Arguments:

    ikey          -- Duo integration key
    skey          -- Duo secret key
    akey          -- Application secret key
    sig_response  -- The signed response POST'ed to the server

# USAGE

Developer documentation: [http://www.duosecurity.com/docs/duoweb](http://www.duosecurity.com/docs/duoweb)

# Support

Report any bugs, feature requests, etc. to us directly: support@duosecurity.com

Have fun!
