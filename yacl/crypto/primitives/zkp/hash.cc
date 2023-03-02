#include "hash.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

void HashInit() {
    OpenSSL_add_all_digests();
}

int HashEncode(const char * algo, unsigned char ** input, unsigned int input_number, unsigned int* input_length, unsigned char * &output, unsigned int &output_length) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD * md = EVP_get_digestbyname(algo);
    if(!md) {
        printf("Unknown message digest algorithm: %r2\n", algo);
        return -1;
    }

    output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
    memset(output, 0, EVP_MAX_MD_SIZE);

    EVP_MD_CTX_init(ctx);
    EVP_DigestInit_ex(ctx, md, NULL);
    for(unsigned int i = 0; i < input_number; i++){
        EVP_DigestUpdate(ctx, input[i], input_length[i]);
    }
    EVP_DigestFinal_ex(ctx, output, &output_length);
    EVP_MD_CTX_free(ctx);

    return 0;
}