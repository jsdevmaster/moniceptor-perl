#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use CGI::Carp qw(fatalsToBrowser warningsToBrowser);
use DBI;
use JSON;

# Load your custom module
use lib '/usr/lib/cgi-bin/moniceptor-perl';  # Add path where mysubs.pm is located
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

# Get form parameters - convert state values to 2-letter codes
my %params = (
    first_name              => $cgi->param('first_name') || '',
    middle_initial          => $cgi->param('middle_initial') || '',
    last_name               => $cgi->param('last_name') || '',
    residence_address_line1 => $cgi->param('residence_address_line1') || '',
    residence_address_line2 => $cgi->param('residence_address_line2') || '',
    residence_city          => $cgi->param('residence_city') || '',
    residence_state         => _extract_state_code($cgi->param('residence_state')) || '',
    residence_zip           => $cgi->param('residence_zip') || '',
    primary_email           => $cgi->param('primary_email') || '',
    secondary_email         => $cgi->param('secondary_email') || '',
    mobile_phone            => $cgi->param('mobile_phone') || '',
    home_phone              => $cgi->param('home_phone') || '',
    work_phone              => $cgi->param('work_phone') || '',
    work_phone_ext          => $cgi->param('work_phone_ext') || '',
    mailing_address_line1   => $cgi->param('mailing_address_line1') || '',
    mailing_address_line2   => $cgi->param('mailing_address_line2') || '',
    mailing_city            => $cgi->param('mailing_city') || '',
    mailing_state           => _extract_state_code($cgi->param('mailing_state')) || '',
    mailing_zip             => $cgi->param('mailing_zip') || '',
    password                => $cgi->param('password') || '',
);

my $response = {};

# Validate required fields
my @errors;
push @errors, "First name is required" unless $params{first_name};
push @errors, "Last name is required" unless $params{last_name};
push @errors, "Residence address line 1 is required" unless $params{residence_address_line1};
push @errors, "Residence city is required" unless $params{residence_city};
push @errors, "Residence state is required" unless $params{residence_state};
push @errors, "Residence ZIP code is required" unless $params{residence_zip};
push @errors, "Primary email is required" unless $params{primary_email};
push @errors, "Password is required" unless $params{password};

# Use email validation from mysubs.pm
unless (MySubs::email_ok('MySubs', \$cgi, \$params{primary_email})) {
    push @errors, "Primary email format is invalid";
}
if ($params{secondary_email} && !MySubs::email_ok('MySubs', \$cgi, \$params{secondary_email})) {
    push @errors, "Secondary email format is invalid";
}

# Use zip validation from mysubs.pm
unless (MySubs::zip_ok('MySubs', \$cgi, \$params{residence_zip})) {
    push @errors, "Residence ZIP code format is invalid";
}
if ($params{mailing_zip} && !MySubs::zip_ok('MySubs', \$cgi, \$params{mailing_zip})) {
    push @errors, "Mailing ZIP code format is invalid";
}

# Use phone validation from mysubs.pm if phone numbers are provided
if ($params{mobile_phone} && !MySubs::phone_ok('MySubs', \$cgi, \$params{mobile_phone})) {
    push @errors, "Mobile phone format is invalid";
}
if ($params{home_phone} && !MySubs::phone_ok('MySubs', \$cgi, \$params{home_phone})) {
    push @errors, "Home phone format is invalid";
}
if ($params{work_phone} && !MySubs::phone_ok('MySubs', \$cgi, \$params{work_phone})) {
    push @errors, "Work phone format is invalid";
}

# If there are validation errors, return error response
if (@errors) {
    $response = {
        success => 0,
        errors => \@errors
    };
    print encode_json($response);
    exit;
}

# Check if email already exists
eval {
    my $check_sth = $dbh->prepare("SELECT id FROM user_info WHERE primary_email = ?");
    $check_sth->execute($params{primary_email});
    if ($check_sth->fetchrow_hashref) {
        $response = {
            success => 0,
            errors => ["Primary email already exists in our system"]
        };
        print encode_json($response);
        exit;
    }
};

if ($@) {
    # Database error during email check
    $response = {
        success => 0,
        errors => ["Database error: Unable to check email availability"]
    };
    print encode_json($response);
    exit;
}

# Hash the password using the function from mysubs.pm
my $password_hash = MySubs::hash_password_bcrypt('MySubs', $params{password});

# Generate default values for mac and location
my $default_mac = _generate_default_mac();

# Insert user into database
eval {
    my $insert_sth = $dbh->prepare("
        INSERT INTO user_info (
            password, first_name, middle_initial, last_name,
            residence_address_line1, residence_address_line2, residence_city, 
            residence_state, residence_zip, primary_email, secondary_email,
            mobile_phone, home_phone, work_phone, work_phone_ext,
            mailing_address_line1, mailing_address_line2, mailing_city,
            mailing_state, mailing_zip, mac, location
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ST_PointFromText('POINT(0 0)', 4326))
    ");
    
    $insert_sth->execute(
        $password_hash,
        $params{first_name},
        $params{middle_initial},
        $params{last_name},
        $params{residence_address_line1},
        $params{residence_address_line2},
        $params{residence_city},
        $params{residence_state},
        $params{residence_zip},
        $params{primary_email},
        $params{secondary_email},
        $params{mobile_phone},
        $params{home_phone},
        $params{work_phone},
        $params{work_phone_ext},
        $params{mailing_address_line1},
        $params{mailing_address_line2},
        $params{mailing_city},
        $params{mailing_state},
        $params{mailing_zip},
        $default_mac
        # location is handled in the SQL with ST_PointFromText
    );
    
    my $user_id = $dbh->last_insert_id(undef, undef, undef, undef);
    
    # Return success response
    $response = {
        success => 1,
        message => "Registration successful!",
        username => $params{primary_email}  # Using email as username
    };
};

if ($@) {
    # Handle database errors gracefully
    my $error_message = $@;
    # Log the actual error for debugging
    warn "Database error: $error_message";
    
    $response = {
        success => 0,
        errors => ["System error: Unable to process registration. Please try again later."]
    };
}

print encode_json($response);

# Helper function to extract 2-letter state codes from your form values
sub _extract_state_code {
    my ($state_value) = @_;
    return '' unless $state_value;
    
    # If it's already a 2-letter code, return it
    return $state_value if $state_value =~ /^[A-Z]{2}$/;
    
    # Extract from values like "residence_AL", "mailing_CA", etc.
    if ($state_value =~ /_(A[LKRSZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AT]|W[AIVY])$/) {
        return $1;
    }
    
    return '';
}

# Generate a default MAC address (12 characters without colons)
sub _generate_default_mac {
    my @hex_chars = ('0'..'9', 'A'..'F');
    my $mac = '';
    
    # Generate 12 random hex characters
    for (1..12) {
        $mac .= $hex_chars[int(rand(scalar @hex_chars))];
    }
    
    return $mac;
}