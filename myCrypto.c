/*----------------------------------------------------------------------------
PA-03: Big Integers & Elgamal Digital Signature

FILE:   myCrypto.c

Written By: 
     1- Ryan Lewis
     2- Martin Quezada
     
Submitted on: 11/1/2020
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// LAB-01
//***********************************************************************

void handleErrors(char *msg)
{
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

unsigned encrypt(uint8_t *pPlainText, unsigned plainText_len,
                 uint8_t *key, uint8_t *iv, uint8_t *pCipherText)
{
    int status;
    unsigned len = 0, encryptedLen = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("encrypt: failed to creat CTX");

    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");

    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptUpdate");
    encryptedLen += len;

    // If additional ciphertext may still be generated,
    // the pCipherText pointer must be first advanced forward
    pCipherText += len;

    // Finalize the encryption.
    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len; // len could be 0 if no additional cipher text was generated

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt(uint8_t *pCipherText, unsigned cipherText_len,
                 uint8_t *key, uint8_t *iv, uint8_t *pDecryptedText)
{
    int status;
    unsigned len = 0, decryptedLen = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("decrypt: failed to creat CTX");

    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");

    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;

    // If additionl decrypted text may still be generated,
    // the pDecryptedText pointer must be first advanced forward
    pDecryptedText += len;

    // Finalize the decryption.
    status = EVP_DecryptFinal_ex(ctx, pDecryptedText, &len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************

int encryptFile(int fd_in, int fd_out, unsigned char *key, unsigned char *iv)
{
    static uint8_t plainText[PLAINTEXT_LEN_MAX];
    // EVP docs state that up to PLAIN_LEN_MAX + cipher_block_size - 1 can be written by update
    static uint8_t cipherText[CIPHER_LEN_MAX];
    int status;
    unsigned len = 0, encryptedLen = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("encrypt: failed to creat CTX");

    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
    {
        handleErrors("encrypt: failed to EncryptInit_ex");
    }

    int m = 0;
    ssize_t n;
    // Read chunks of data from the input fd until EOF is reached
    while ((n = read(fd_in, plainText, PLAINTEXT_LEN_MAX)) > 0)
    {
        // Call encrypt update for every chunk read
        status = EVP_EncryptUpdate(ctx, cipherText, &len, plainText, n);
        if (status != 1)
        {
            handleErrors("encrypt: failed to EncryptUpdate");
        }

        encryptedLen += len;
        // Write ciphertext to the output fd
        m = write(fd_out, cipherText, len);
        if (m != len)
        {
            handleErrors("encrypt: write length differs from ciphertext length");
        }
    }

    // Finalize encryption and write final block to ciphertext buffer
    status = EVP_EncryptFinal_ex(ctx, cipherText, &len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");

    encryptedLen += len;

    // Write final block to the output fd
    m = write(fd_out, cipherText, len);
    if (m != len)
    {
        handleErrors("encrypt: failed to write the last ciphertext block.");
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;
}

//-----------------------------------------------------------------------------
int decryptFile(int fd_in, int fd_out, unsigned char *key, unsigned char *iv)
{
    static uint8_t cipherText[CIPHER_LEN_MAX];
    // EVP docs state that up to CIPHER_LEN_MAX + cipher_block_size - 1 can be written by update
    // DECRYPTED_LENmAX ??
    static uint8_t decryptedText[CIPHER_LEN_MAX];
    int status;
    unsigned len = 0, decryptedLen = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("decrypt: failed to creat CTX");

    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");

    int m = 0;
    ssize_t n;
    // Read chunks of data from the input fd until EOF is reached
    while ((n = read(fd_in, cipherText, CIPHER_LEN_MAX)) > 0)
    {
        // Decrypt every chunk of ciphertext data
        status = EVP_DecryptUpdate(ctx, decryptedText, &len, cipherText, n);
        if (status != 1)
            handleErrors("decrypt: failed to DecryptUpdate");

        decryptedLen += len;
        // write decrypted text to output fd
        m = write(fd_out, decryptedText, len);
        if (m != len)
        {
            handleErrors("decrypt: write length differs from decrypted text length");
        }
    }

    // Finalize the decryption.
    status = EVP_DecryptFinal_ex(ctx, decryptedText, &len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    // Write final block to output fd
    m = write(fd_out, decryptedText, len);
    if (m != len)
    {
        handleErrors("decrypt: failed to write to the last decrypted block.");
    }
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;
}

//***********************************************************************
// LAB-02
//***********************************************************************

RSA *getRSAfromFile(char *filename, int public)
{
    RSA *rsa;
    // open the binary file whose name if 'filename' for reading
    FILE *rsa_file = fopen(filename, "r");
    if (rsa_file == NULL)
        handleErrors("getRSA: failed to open file");
    // Create a new RSA object using RSA_new() ;
    rsa = RSA_new();
    // To read a public RSA key, use PEM_read_RSA_PUBKEY()
    if (public)
    {
        rsa = PEM_read_RSA_PUBKEY(rsa_file, &rsa, NULL, NULL);
    }
    else // To read a public RSA key, use PEM_read_RSAPrivateKey()sss
    {
        rsa = PEM_read_RSAPrivateKey(rsa_file, &rsa, NULL, NULL);
    }
    // close the binary file 'filename'
    fclose(rsa_file);

    return rsa;
}

//***********************************************************************
// PA-02
//***********************************************************************

size_t fileDigest(int fd_in, int fd_out, uint8_t *digest)
// Read all the incoming data stream from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, write a copy of the incoming data stream
// file to 'fd_out'
// Returns actual size in bytes of the computed hash (a.k.a. digest value)
{
    static uint8_t chunkBuf[INPUT_CHUNK];
    unsigned digestLen = 0;
    // Use EVP_MD_CTX_create() to create new hashing context
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    // Initialize the context using EVP_DigestInit() so that it deploys
    // the EVP_sha256() hashing function
    EVP_DigestInit(ctx, EVP_sha256());

    while (read(fd_in, chunkBuf, INPUT_CHUNK) > 0)
    {
        // Use EVP_DigestUpdate() to hash the data you read
        EVP_DigestUpdate(ctx, chunkBuf, INPUT_CHUNK);

        if (fd_out > 0) // write the data you just read to fd_out
        {
            if (write(fd_out, chunkBuf, INPUT_CHUNK) != INPUT_CHUNK)
            {
                EVP_MD_CTX_destroy(ctx);
                handleErrors("fileDigest: failed to write data to fd_out.");
            }
        }
    }

    // Finialize the hash calculation using EVP_DigestFinal() directly
    // into the 'digest' array
    EVP_DigestFinal(ctx, digest, &digestLen);

    // Use EVP_MD_CTX_destroy( ) to clean up the context
    EVP_MD_CTX_destroy(ctx);

    // return the length of the computed digest in bytes ;
    return digestLen;
}

//***********************************************************************
// PA-03
//***********************************************************************

/* Sends the # of bytes, followed by the bytes themselves of a BIGNUM's
   value to file descriptor fd_out
   Returns 1 on success, 0 on failure */
int BN_write_fd( int fd_out  , const BIGNUM *bn ) {
    
    // TODO
    return 0;
}

/* Read the # of bytes, then the bytes themselves of a BIGNUM's value from
   file descriptor fd_in
   Returns: a newly-created BIGNUM, which should be freed later by the caller
            or NULL on failure */
BIGNUM *BN_read_fd ( int fd_in ) {
    
    // TODO
    return NULL;
}

/* Returns a newly-created random BIGNUM such that: 1 < BN's value < (p-1) */
BIGNUM *BN_myRandom( const BIGNUM *p ) {
    
    BIGNUM *max = BN_new();
    BIGNUM *rnd = BN_new();

    BN_copy( max, p );
    BN_sub_word( max, 3 );
    BN_rand_range( rnd, max );
    BN_add_word( rnd, 2 );

    BN_clear_free( max );
    return rnd;
}

/* Use the prime 'q', the primitive root 'gen,' and the private 'x' to
   compute the Elgamal signature (r,s) on the 'len'-byte long 'digest' */
void elgamalSign( const uint8_t *digest , int len ,  
                     const BIGNUM *q , const BIGNUM *gen , const BIGNUM *x , 
                     BIGNUM *r , BIGNUM *s , BN_CTX *ctx ) {
    // TODO
}

/* Use the prime 'q', the primitive root 'gen', and the public 'y' to
   validate the Elgamal signature (r,s) on the 'len'-byte long 'digest'
   Return 1 if valid, 0 otherwise */
int elgamalValidate( const uint8_t *digest , int len ,  
                  const BIGNUM *q , const BIGNUM *gen , const BIGNUM *y , 
                  BIGNUM *r , BIGNUM *s , BN_CTX *ctx ) {
    // TODO
    return 0;
}

