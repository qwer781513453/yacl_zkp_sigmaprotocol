#ifndef SIGMAPROTOCOL_HASH_H
#define SIGMAPROTOCOL_HASH_H

void HashInit();

int HashEncode(const char *algo, unsigned char **input,
               unsigned int input_number, unsigned int *input_length,
               unsigned char *&output, unsigned int &output_length);

#endif  // SIGMAPROTOCOL_HASH_H
