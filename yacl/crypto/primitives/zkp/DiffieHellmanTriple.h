#ifndef SIGMAPROTOCOL_DIFFIEHELLMANTRIPLE_H
#define SIGMAPROTOCOL_DIFFIEHELLMANTRIPLE_H

#include "SigmaProtocol.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

// Relation R of Diffie-Hellman triple: (Y1,Y2,Y3), Prover wants to prove that
// Y1 = w1*G, Y2 = w2*G, Y3 = (w1w2)*G, the required multiplicative relation can be proven
// by observing that the proof goal is equivalent to Y1 = w1*G, Y2=w2*G and Y3 = w2*Y1

namespace yacl::crypto{

class DiffieHellmanTripleCommonInput: public SigmaProtocolCommonInput {
public:
    DiffieHellmanTripleCommonInput(const EC_GROUP* Group, const EC_POINT* G, const EC_POINT* Y1,
                                   const EC_POINT* Y2, const EC_POINT* Y3, const char* HashName = "sha256")
                                :Group(Group),G(G),Y1(Y1),Y2(Y2),Y3(Y3),SigmaProtocolCommonInput(HashName)
                                { p = EC_GROUP_get0_order(Group); }

    const EC_GROUP* getGroup() const { return this->Group; }

    const BIGNUM* getP() const { return this->p; }

    const EC_POINT * getY1() const { return this->Y1; }

    const EC_POINT * getY2() const { return this->Y2; }

    const EC_POINT * getY3() const { return this->Y3; }

    const EC_POINT * getG() const { return this->G; }

private:
    const EC_GROUP* Group;

    const BIGNUM* p;

    const EC_POINT* Y1;

    const EC_POINT* Y2;

    const EC_POINT* Y3;

    const EC_POINT* G;

};

class DiffieHellmanTripleProverInput: public SigmaProtocolProverInput {
public:
    DiffieHellmanTripleProverInput(const BIGNUM* w1, const BIGNUM* w2): w1(w1), w2(w2) {}

    const BIGNUM* getW1() const { return this->w1; }

    const BIGNUM* getW2() const { return this->w2; }

private:
    const BIGNUM* w1;

    const BIGNUM* w2;

};

class DiffieHellmanTripleMessage: public SigmaProtocolResponseMessage {
public:
    explicit DiffieHellmanTripleMessage(const EC_GROUP* Group): Group(Group),T1(EC_POINT_new(Group)), T2(EC_POINT_new(Group)),
                                                                T3(EC_POINT_new(Group)), s1(BN_new()), s2(BN_new()) {}

    DiffieHellmanTripleMessage(const EC_GROUP* Group, const EC_POINT* T1, const EC_POINT* T2,
                               const EC_POINT* T3, const BIGNUM* s1, const BIGNUM* s2);

    DiffieHellmanTripleMessage(const DiffieHellmanTripleMessage &Msg);

    ~DiffieHellmanTripleMessage(){
        EC_POINT_free(T1);
        EC_POINT_free(T2);
        EC_POINT_free(T3);
        BN_free(s1);
        BN_free(s2);
    }

    const EC_GROUP* Group;

    // Prover'r2 first message
    EC_POINT* T1;  // T1 = w2*G

    EC_POINT* T2;  // T2 = r2*G

    EC_POINT* T3;  // T3 = r2*Y1

    // Prover'r2 second message
    BIGNUM* s1; // s1 = w2 + cw1

    BIGNUM* s2; // s2 = r2 + cw2

};

class DiffieHellmanTripleProver: public SigmaProtocolProver {
public:
    DiffieHellmanTripleProver(const DiffieHellmanTripleCommonInput &params,
                              const DiffieHellmanTripleProverInput &input)
                                : params(params), input(input), r1(BN_new()),r2(BN_new()),
                                Msg(params.getGroup()),flag1(0),flag2(0) {}

    void ComputeFirstMessage() override;

    void ComputeSecondMessage() override;

    DiffieHellmanTripleMessage getMsg() {
        if(!flag1)
            throw std::invalid_argument("FirstMessage hasn't been calculated yet. Try to run ComputeFirstMessage()");
        if(!flag2)
            throw std::invalid_argument("SecondMessage hasn't been calculated yet. Try to run ComputeSecondMessage()");
        return this->Msg;
    };

private:
    const DiffieHellmanTripleCommonInput &params;

    const DiffieHellmanTripleProverInput &input;

    // random element
    BIGNUM* r1;

    BIGNUM* r2;

    DiffieHellmanTripleMessage Msg;

    bool flag1, flag2;
};

class DiffieHellmanTripleVerifier: public SigmaProtocolVerifier {
public:
    DiffieHellmanTripleVerifier(const DiffieHellmanTripleCommonInput &params, const DiffieHellmanTripleMessage &Msg)
                            :params(params),Msg(Msg){}

    bool Verify() override;
private:
    const DiffieHellmanTripleCommonInput &params;

    const DiffieHellmanTripleMessage &Msg;
};

BIGNUM* DiffieHellmanTripleGetChallenge(const DiffieHellmanTripleCommonInput &params,
                                        const DiffieHellmanTripleMessage &Msg,
                                        BN_CTX* ctx);

}



#endif //SIGMAPROTOCOL_DIFFIEHELLMANTRIPLE_H
