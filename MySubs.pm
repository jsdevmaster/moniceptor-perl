# mysubs.pm
package MySubs;
require Exporter;
our @ISA = qw(Exporter);

use strict;
use warnings;
use Exporter qw(import);

our @EXPORT = qw(init password_ok zip_ok phone_ok email_ok hash_password_bcrypt verify_password);

sub init {
    my ($class, $q, $fields, $missing_field, $input_field) = @_;
    # Initialization logic here if needed
}

sub email_ok {
    my ($class, $q, $email) = @_;
    if (defined $$email && $$email =~ /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/) {
        return 1;
    } 
    else {
        return 0;        
    }
}

sub password_ok {
    my ($class, $password) = @_;
    my $min_length = 8;
    my $has_digit = 0;
    my $has_uppercase = 0;
    my $has_lowercase = 0;
    my $has_punct = 0;

    # Check minimum length
    return 0 unless length($$password) >= $min_length;

    # Check for character types
    $has_digit++     if $$password =~ /\d/;
    $has_uppercase++ if $$password =~ /[A-Z]/;
    $has_lowercase++ if $$password =~ /[a-z]/;
    $has_punct++     if $$password =~ /[\p{Punct}]/;

    # Return true if all conditions are met
    return ($has_digit && $has_uppercase && $has_lowercase && $has_punct);
}

sub zip_ok {
    my ($class, $q, $zip_code) = @_;
     
    $$zip_code =~ s/\s+//gs;
    $$zip_code =~ s/\\//gsm;

    if($$zip_code !~ /^\d{5}(?:[-\s]\d{4})?$/) {
        return 0;
    }
    else {
        return 1;        
    }
}

sub phone_ok {
    my ($class, $q, $phone_number) = @_;
    
    my $db_phone_number = $$phone_number;
    $db_phone_number =~ s/^(?:\+?(1)[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$/$2-$3-$4/;

    if($$phone_number !~ /^(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$/x) {
        return 0;
    }
    else {
        $$phone_number = $db_phone_number;
        return 1;        
    }
}

# Hash password using bcrypt
sub hash_password_bcrypt {
    my ($class, $password) = @_;
    
    # Use the simple crypt() method that always works
    my @salt_chars = ('.', '/', 'A'..'Z', 'a'..'z', '0'..'9');
    my $salt = '';
    $salt .= $salt_chars[int(rand(scalar @salt_chars))] for 1..22;
    
    my $settings = '$2b$12$' . $salt;
    my $hash = crypt($password, $settings);
    
    return $hash;
}

# Verify password against stored hash
sub verify_password {
    my ($class, $password, $stored_hash) = @_;
    
    # If the stored hash is a bcrypt hash (starts with $2a$, $2b$, or $2y$)
    if ($stored_hash =~ /^\$2[aby]\$/) {
        # Use crypt to verify bcrypt password
        my $calculated_hash = crypt($password, $stored_hash);
        return $calculated_hash eq $stored_hash;
    }
    
    # If using SHA-256 (fallback from your registration)
    eval {
        require Digest::SHA;
        Digest::SHA->import('sha256_hex');
        my $hashed_password = Digest::SHA::sha256_hex($password);
        return $hashed_password eq $stored_hash;
    };
    
    # Final fallback - direct comparison (not recommended for production)
    return $password eq $stored_hash;
}

1;