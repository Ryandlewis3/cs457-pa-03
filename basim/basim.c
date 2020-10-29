/*----------------------------------------------------------------------------
PA-03 Big Integers & Elgamal Digital Signatures using openSSL

Written By:  1- Martin Quezada
             2- Ryan Lewis

             Submitted on: 11/1/2020
----------------------------------------------------------------------------*/
/*

    Adapted from:
        http://hayageek.com/rsa-encryption-decryption-openssl-c/
*/

#include "../myCrypto.h"

void main(int argc, char *argv[])
{

    int control_fd, data_fd;

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
    FILE *log = fopen("basim/logBasim.txt", "w");
    if (!log)
    {
        fprintf(stderr, "Basim: Could not create log file\n");
        exit(-1);
    }

    fprintf(log, "This is Basim's Executable by Ryan & Martin\n");
    fprintf(log, "Reading from control FD: %d and data FD: %d\n\n",
        control_fd, data_fd);

    // Get DH parameters sent by Amal over AtoB Control pipe
    // Will be in this order: the prime, the primitive root, Amal's public y
    BIGNUM *prime = BN_read_fd( control_fd );
    if( prime == NULL ) {
        handleErrors("BN_read_fd");
    }
    BIGNUM *root = BN_read_fd( control_fd );
    if( root == NULL ) {
        handleErrors("BN_read_fd");
    }
    BIGNUM *y = BN_read_fd( control_fd );
    if( y == NULL ) {
        handleErrors("BN_read_fd");
    }

    // Display hex of parameters received in log file
    fprintf(log, "Basim: I received these parameters from Amal (Hex):\n");
    char *hexPrime, *hexRoot, *hexY;
    hexPrime = BN_bn2hex(prime);
    hexRoot = BN_bn2hex(root);
    hexY = BN_bn2hex(y);

    fprintf(log, "   Prime        : %s\n", hexPrime);
    fprintf(log, "   Root         : %s\n", hexRoot);
    fprintf(log, "   Public value : %s\n\n", hexY);

    // Call fileDigest() to receive the incoming data over AtoB Data pipe
    // and compute its SHA256 hash value, while saving a copy of the file as
    // bunnyCopy.mp4 file in the pa-03 folder

    fprintf(log, "Basim: computing digest from incoming file\n");

    int copy_fd = open("bunnyCopy.mp4", O_RDWR | O_CREAT, S_IRWXU);
    uint8_t *digest;
    size_t digestSize = fileDigest(data_fd, copy_fd, digest);

    fprintf(log, "Basim: Here is my digest of the incoming file:\n");
    BIO_dump_fp(log, (const char *)digest, digestSize);

    // Receive Amal's digital signature (r,s) over the AtoB Control pipe
    BIGNUM *r = BN_read_fd( control_fd );
    if( r == NULL ) {
        handleErrors("BN_read_fd");
    }
    BIGNUM *s = BN_read_fd( control_fd );
    if( s == NULL ) {
        handleErrors("BN_read_fd");
    }

    fprintf(log, "Basim: Received this signature from Amal:\n");

    char *hexR, *hexS;
    hexR = BN_bn2hex(r);
    hexS = BN_bn2hex(s);

    fprintf(log, "   r : %s\n", hexR);
    fprintf(log, "   s : %s\n\n", hexS);

    // Verify Amal's signature by calling elgamalValidate() function
    if( elgamalValidate( digest, digestSize, prime, root, y, r, s, ctx ) == 0 )
    {
        handleErrors("Could not validate Amal's signature");
    }
    
    fprintf(log, "Basim: This signature is VALID\n");

    // Clean up
    BN_clear_free( root );
    BN_clear_free( prime );
    BN_clear_free( r );
    BN_clear_free( s );
    BN_clear_free( y );
    BN_CTX_free( ctx );
}

