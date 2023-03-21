#ifndef SIGMAPROTOCOL_HASH_H
#define SIGMAPROTOCOL_HASH_H
#include <vector>

void HashInit();

int HashEncode(const char *algo, unsigned char **input,
               unsigned int input_number, unsigned int *input_length,
               unsigned char *&output, unsigned int &output_length);

int HashEncode(const char *algo, std::vector<unsigned char *> input,
               std::vector<unsigned int> input_length, unsigned char *&output,
               unsigned int &output_length);

#endif  // SIGMAPROTOCOL_HASH_H
