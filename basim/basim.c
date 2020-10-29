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
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Get AtoB Control and Data file descriptor from the argv[]
    fd_control = strtol(argv[1], &argv[1], 10);
    fd_data = strtol(argv[2], &argv[2], 10);
    
    // Open Log File
    FILE *log = fopen("basim/logBasim.txt", "w");
    if (!log)
    {
        fprintf(stderr, "Basim: Could not create log file\n");
        exit(-1);
    }

    // Get DH parameters sent by Amal over AtoB Control pipe
    // Will be in this order: the prime, the primitive root, Amal's public y


    // Call fileDigest() to receive the incoming data over AtoB Data pipe
    // and compute its SHA256 hash value, while saving a copy of the file as
    // bunnyCopy.mp4 file in the pa-03 folder


    // Receive Amal's digital signature (r,s) over the AtoB Control pipe


    // Verify Amal's signature by calling elgamalValidate() function


    // Clean up

}

