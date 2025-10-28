#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use CGI::Carp qw(fatalsToBrowser warningsToBrowser);
use DBI;
use Crypt::JWT qw(encode_jwt);
use JSON;

# Load your custom module
use lib '/usr/lib/cgi-bin/moniceptor-perl';
use MySubs;

require '/usr/lib/cgi-bin/moniceptor-perl/config.pl';
our $dbh;

my $cgi = CGI->new;

# Set CORS headers to allow requests from any origin
print $cgi->header(
    -type => 'application/json',
    -access_control_allow_origin => '*',
    -access_control_allow_methods => 'GET, POST, OPTIONS',
    -access_control_allow_headers => 'Content-Type'
);

# Handle preflight OPTIONS request
if ($cgi->request_method() eq 'OPTIONS') {
    exit;
}

# Get form parameters
my $email = $cgi->param('email') || '';
my $password = $cgi->param('password') || '';

my $response = {};

# Validate required fields
if (!$email || !$password) {
    $response = {
        success => 0,
        errors => ["Email and password are required"]
    };
    print encode_json($response);
    exit;
}

# Validate email format
unless (MySubs::email_ok('MySubs', \$cgi, \$email)) {
    $response = {
        success => 0,
        errors => ["Invalid email format"]
    };
    print encode_json($response);
    exit;
}

# Authenticate user
eval {
    # Get user by email including password hash
    my $sth = $dbh->prepare("SELECT id, password, first_name, last_name, primary_email FROM user_info WHERE primary_email = ?");
    $sth->execute($email);
    my $user = $sth->fetchrow_hashref;

    if (!$user) {
        $response = {
            success => 0,
            errors => ["Invalid email or password"]
        };
        print encode_json($response);
        exit;
    }

    # Verify password using the function from mysubs.pm
    if (MySubs::verify_password('MySubs', $password, $user->{password})) {
        # Password is correct - login successful
        
        # Generate JWT token
        my $payload = { 
            user_id => $user->{id},
            email => $user->{primary_email},
            first_name => $user->{first_name},
            last_name => $user->{last_name},
            exp => time() + 3600  # 1 hour expiration
        };
        
        my $token;
        eval {
            $token = encode_jwt(payload => $payload, key => 'supersecretkey', alg => 'HS256');
        };
        
        if ($@) {
            # JWT encoding failed, use simple success response
            $response = {
                success => 1,
                message => "Login successful!",
                user => {
                    id => $user->{id},
                    first_name => $user->{first_name},
                    last_name => $user->{last_name},
                    email => $user->{primary_email}
                }
            };
        } else {
            # JWT encoding successful
            $response = {
                success => 1,
                message => "Login successful!",
                token => $token,
                user => {
                    id => $user->{id},
                    first_name => $user->{first_name},
                    last_name => $user->{last_name},
                    email => $user->{primary_email}
                }
            };
        }
    } else {
        $response = {
            success => 0,
            errors => ["Invalid email or password"]
        };
    }
};

if ($@) {
    # Handle database errors gracefully
    my $error_message = $@;
    warn "Database error during login: $error_message";
    
    $response = {
        success => 0,
        errors => ["System error: Unable to process login. Please try again later."]
    };
}

print encode_json($response);