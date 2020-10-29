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
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

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

    // Generate a 512-bit prime number whose primitive root is equal to 2
    // Use DH_generate_parameters_ex() and DH_get0_pqg()
    // Make sure the number is actually prime by calling BN_is_prime_ex()


    // Randomly select private value x and compute corresponding value y


    // Send all previous values (except for x) to Basim over AtoB Control pipe
    // Must be in this order: the prime, the primitive root, public value y


    // Open bunny.mp4 and call fileDigest() to compute the SHA256 hash value
    // while transmitting a copy of the file over the AtoB Data pipe


    // Use Amal's DH parameters to digitally sign the digest computed according
    // to the Elgamal Digital Signature scheme


    // Transmit Amal's digital signature to Basim over the AtoB Control pipe
    // Must be in this order: the value 'r', the value 's'


    // Clean up

}

