//
// Created by wx on 23-1-3.
//

#ifndef SIGMAPROTOCOL_SCHNORR_H
#define SIGMAPROTOCOL_SCHNORR_H
#include "SigmaProtocol.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
namespace yacl::crypto {

class SchnorrCommonInput: public SigmaProtocolCommonInput{
public:
    SchnorrCommonInput(const EC_GROUP *Group, const EC_POINT* G, const EC_POINT* H, const char* HashName = "sha256")
                    : Group(Group), G(G), H(H),SigmaProtocolCommonInput(HashName)
    {
        this->p = EC_GROUP_get0_order(Group);
    }

    const EC_GROUP* getGroup() const { return this->Group; }

    const BIGNUM* getP() const { return this->p; }

    const EC_POINT* getG() const { return this->G; }

    const EC_POINT* getH() const { return this->H; }

private:
    const EC_GROUP *Group;

    const EC_POINT* G; // a generator with order p

    const EC_POINT* H; // H = G^{w}

    const BIGNUM *p; //

};

class SchnorrProverInput: public SigmaProtocolProverInput{
public:
    SchnorrProverInput(const BIGNUM* w): w(w) {}

    const BIGNUM* getW() const { return w; }

private:
    const BIGNUM *w; // witness, G^{w} = H
};

class SchnorrMessage: public SigmaProtocolResponseMessage{
public:
    SchnorrMessage(const EC_GROUP* Group): Group(Group), T(EC_POINT_new(Group)),s(BN_new()) {}

    SchnorrMessage(const EC_GROUP* Group, const EC_POINT* T, const BIGNUM* s)
                : Group(Group), T(EC_POINT_new(Group)), s(BN_new())
    {
        EC_POINT_copy(this->T, T);
        BN_copy(this->s, s);
    }

    SchnorrMessage(const SchnorrMessage &Msg)
            : Group(Msg.Group), T(EC_POINT_new(Group)), s(BN_new())
    {
        EC_POINT_copy(this->T, Msg.T);
        BN_copy(this->s, Msg.s);
    }

    ~SchnorrMessage(){
        EC_POINT_free(T);
        BN_free(s);
    }

    const EC_GROUP* Group;

    EC_POINT* T;

    BIGNUM* s;

};

class SchnorrProver: public SigmaProtocolProver{
public:
    SchnorrProver(const SchnorrCommonInput &params, const SchnorrProverInput &input)
                : params(params), input(input), Msg(params.getGroup()),r(BN_new()), flag1(0), flag2(0) {}

    void ComputeFirstMessage() override;

    void ComputeSecondMessage() override;

    SchnorrMessage getMsg(){
        if(!flag1)
            throw std::invalid_argument("FirstMessage hasn't been calculated yet. Try to run ComputeFirstMessage()");
        if(!flag2)
            throw std::invalid_argument("SecondMessage hasn't been calculated yet. Try to run ComputeSecondMessage()");
        return this->Msg;
    }

private:
    BIGNUM *r; // random element

    const SchnorrCommonInput &params;

    const SchnorrProverInput &input;

    SchnorrMessage Msg;

    bool flag1, flag2;
};

class SchnorrVerifier: public SigmaProtocolVerifier{
public:
    SchnorrVerifier(const SchnorrCommonInput &params, const SchnorrMessage &Msg)
                : params(params), Msg(Msg) {}

    bool Verify() override;
private:
    const SchnorrCommonInput &params;

    const SchnorrMessage &Msg;
};

BIGNUM* SchnorrGetChallenge(const SchnorrCommonInput &params, const SchnorrMessage &Msg, BN_CTX* ctx);

}

#endif //SIGMAPROTOCOL_SCHNORR_H
