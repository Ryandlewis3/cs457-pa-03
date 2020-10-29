/*----------------------------------------------------------------------------
PA-03 Big Integers & Elgamal Digital Signatures using openSSL

Written By:  1- Ryan Lewis
             2- Martin Quezada

             Submitted on: 11/1/2020
----------------------------------------------------------------------------*/
/*

    Adapted from:
        http://hayageek.com/rsa-encryption-decryption-openssl-c/
*/

#include "../myCrypto.h"

void main(int argc, char *argv[]) 
{

    int bunny_fd, control_fd, data_fd;

    // Initialize the crypto library
    //ERR_load_crypto_strings();
    //OpenSSL_add_all_algorithms();

    BN_CTX *ctx = BN_CTX_new();
    if( ctx == NULL ) {
        handleErrors("BN_CTX_new");
    }

    // Get AtoB Control and Data file descriptor from the argv[]
    control_fd = strtol(argv[1], &argv[1], 10);
    data_fd = strtol(argv[2], &argv[2], 10);

    // Open Log File
    FILE *log = fopen("amal/logAmal.txt", "w");
    if (!log)
    {
        fprintf(stderr, "Amal: Could not create log file\n");
        exit(-1);
    }

    fprintf(log, "This is Amal's Executable by Ryan & Martin\n");
    fprintf(log, "Writing to control FD: %d and data FD: %d\n",
        control_fd, data_fd);

    // Generate a 512-bit prime number whose primitive root is equal to 2
    // Use DH_generate_parameters_ex() and DH_get0_pqg()
    // Make sure the number is actually prime by calling BN_is_prime_ex()
    DH *dh = DH_new();
    const BIGNUM *p, *q, *g;
    BIGNUM *root = BN_new();
    BIGNUM *prime = BN_new();

    if( DH_generate_parameters_ex( dh, 512, 2, NULL ) != 1 ) {
        handleErrors("Amal: DH_generate");
    }

    DH_get0_pqg( dh, &p, &q, &g );

    BN_copy( root, g );
    BN_copy( prime, p );

    DH_free( dh );

    if( BN_is_prime_ex( prime , BN_prime_checks, ctx, NULL ) != 1 ) {
        handleErrors("BN_is_prime_ex()");
    }

    fprintf(log, "Amal: I got a prime\n\n");

    // Randomly select private value x and compute corresponding value y
    BIGNUM *y = BN_new();
    BIGNUM *x = BN_myRandom( prime );

    BN_mod_exp( y, root, x, prime, ctx );

    // Convert parameters and public/private values to hex, display in log file
    char *hexPrime, *hexRoot, *hexX, *hexY;
    hexPrime = BN_bn2hex(prime);
    hexRoot = BN_bn2hex(root);
    hexX = BN_bn2hex(x);
    hexY = BN_bn2hex(y);

    fprintf(log, "Amal: Here are my parameters in hex:\n");
    fprintf(log, "   Prime        : %s\n", hexPrime);
    fprintf(log, "   Root         : %s\n", hexRoot);
    fprintf(log, "   Private value: %s\n", hexX);
    fprintf(log, "   Public value : %s\n\n", hexY);

    fprintf(log, "Amal: sending prime, root and public value to Basim\n");

    // Send all previous values (except for x) to Basim over AtoB Control pipe
    // Must be in this order: the prime, the primitive root, public value y
    if( BN_write_fd( control_fd, prime ) == 0 ) {
        handleErrors("BN_write_fd");
    }
    if( BN_write_fd( control_fd, root ) == 0 ) {
        handleErrors("BN_write_fd");
    }
    if( BN_write_fd( control_fd, y ) == 0 ) {
        handleErrors("BN_write_fd");
    }

    // Open bunny.mp4 and call fileDigest() to compute the SHA256 hash value
    // while transmitting a copy of the file over the AtoB Data pipe

    fprintf(log, "Amal: starting digest of file\n\n");

    bunny_fd = open("bunny.mp4", O_RDONLY);

    uint8_t *digest;
    size_t digestSize = fileDigest(bunny_fd, data_fd, digest);

    fprintf(log, "Amal: here is my digest of the file:\n");
    BIO_dump_fp(log, (const char *)digest, digestSize);

    // Use Amal's DH parameters to digitally sign the digest computed according
    // to the Elgamal Digital Signature scheme

    fprintf(log, "Generating the Elgamal Signature now\n");
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    elgamalSign( digest, digestSize, prime, root, x, r, s, ctx );

    // Display signature in log file as hex
    char *hexR, *hexS;
    hexR = BN_bn2hex(r);
    hexS = BN_bn2hex(s);

    fprintf(log, "   r : %s\n", hexR);
    fprintf(log, "   s : %s\n\n", hexS);

    // Transmit Amal's digital signature to Basim over the AtoB Control pipe
    // Must be in this order: the value 'r', the value 's'
    if( BN_write_fd( control_fd, r ) == 0 ) {
        handleErrors("BN_write_fd");
    }
    if( BN_write_fd( control_fd, s ) == 0 ) {
        handleErrors("BN_write_fd");
    }

    // Clean up
    BN_clear_free( root );
    BN_clear_free( prime );
    BN_clear_free( r );
    BN_clear_free( s );
    BN_clear_free( x );
    BN_clear_free( y );
    BN_CTX_free( ctx );
}

