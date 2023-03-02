#ifndef SIGMAPROTOCOL_SIGMAPROTOCOL_H
#define SIGMAPROTOCOL_SIGMAPROTOCOL_H
#pragma once

#include <iostream>
#include <stdexcept>
#include <cstdio>
#include <openssl/rand.h>
#include "hash.h"

namespace yacl::crypto{

class SigmaProtocolCommonInput{
public:
    SigmaProtocolCommonInput(const char* HashName = "sha256") : HashName(HashName) {}

    const char* HashName;

    virtual ~SigmaProtocolCommonInput() {};
};

class SigmaProtocolProverInput{
public:
    virtual ~SigmaProtocolProverInput() {};
};

class SigmaProtocolResponseMessage
{
public:
    virtual ~SigmaProtocolResponseMessage() {};
};

class SigmaProtocolProver
{
public:
    virtual void ComputeFirstMessage() = 0;

    virtual void ComputeSecondMessage() = 0;

    virtual ~SigmaProtocolProver() {};
};

class SigmaProtocolVerifier
{
public:
    virtual bool Verify() = 0;

    virtual ~SigmaProtocolVerifier() {};

};



}


#endif //SIGMAPROTOCOL_SIGMAPROTOCOL_H
