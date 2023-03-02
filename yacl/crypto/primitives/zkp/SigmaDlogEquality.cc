//
// Created by wx on 23-1-4.
//
#ifndef SIGMAPROTOCOL_SIGMADLOGEQUALITY_CC
#define SIGMAPROTOCOL_SIGMADLOGEQUALITY_CC

#include "SigmaDlogEquality.h"
#include <cassert>

namespace yacl::crypto{

void DlogEqualityProver::ComputeFirstMessage()
{
    // sample a random number w2 in Z_p
    BN_rand_range(this->r, params.getP());

    // compute FirstMessage: two commitments

    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_mul(params.getGroup(), Msg.T1, nullptr, params.getG(), r, ctx);  // T1 = w2*G
    EC_POINT_mul(params.getGroup(), Msg.T2, nullptr, params.getH(), r, ctx);  // T2 = w2*H

    flag1 = true;
    BN_CTX_free(ctx);
}

void DlogEqualityProver::ComputeSecondMessage()
{
    if(!flag1)
        throw std::invalid_argument("The first Message hasn't been calculate yet.Try to run ComputeFirstMessage().\n");

    BN_CTX * ctx = BN_CTX_new();

    // compute the challenge hash(G,H,Y1,Y2,t1,t2)
    BIGNUM * challenge = DlogEqualityGetChallenge(params, Msg, ctx);

    BN_mod_mul(Msg.s, challenge, input.getW(), params.getP(), ctx);
    BN_mod_add(Msg.s, Msg.s, r, params.getP(), ctx);

    flag2 = true;
    BN_CTX_free(ctx);
    BN_free(challenge);
}

bool DlogEqualityVerifier::Verify() {
    BN_CTX * ctx = BN_CTX_new();
    int res = 0;
    int tmp = 0;

    BIGNUM * challenge = DlogEqualityGetChallenge(params, Msg, ctx);

    //verify whether :
    EC_POINT *tmp1 = EC_POINT_new(params.getGroup());
    EC_POINT *tmp2 = EC_POINT_new(params.getGroup());

    // 1) G^r2 = Y1^c*t1
    EC_POINT_mul(params.getGroup(), tmp1, nullptr, params.getG(), Msg.s, ctx);
    EC_POINT_mul(params.getGroup(), tmp2, nullptr, params.getY1(), challenge, ctx);
    EC_POINT_add(params.getGroup(), tmp2, tmp2, Msg.T1, ctx);
    if((tmp = EC_POINT_cmp(params.getGroup(), tmp1, tmp2,ctx) == -1)) goto END;
    res += tmp;

    // 2) H^r2 = Y2^c*t2
    EC_POINT_mul(params.getGroup(), tmp1, nullptr, params.getH(), Msg.s, ctx);
    EC_POINT_mul(params.getGroup(), tmp2, nullptr, params.getY2(), challenge, ctx);
    EC_POINT_add(params.getGroup(), tmp2, tmp2, Msg.T2, ctx);
    if((tmp = EC_POINT_cmp(params.getGroup(), tmp1, tmp2,ctx) == -1)) goto END;
    res += tmp;

END:
    BN_CTX_free(ctx);
    EC_POINT_free(tmp2);
    EC_POINT_free(tmp1);
    BN_free(challenge);
    if(tmp == -1)
        throw std::invalid_argument("EC_POINT_cmp error.\n");

    return (res == 0);
}

// compute hash(G,H,Y1,Y2,T1,T2)
BIGNUM* DlogEqualityGetChallenge(const DlogEqualityCommonInput &params,
                                 const DlogEqualityMessage &Msg,
                                 BN_CTX* ctx)
{
    unsigned char* data[7];
    unsigned int length[7];
    BIGNUM* challenge = BN_new();

    length[0] = EC_POINT_point2buf(params.getGroup(), params.getG(), POINT_CONVERSION_COMPRESSED, &data[0], ctx);
    length[1] = EC_POINT_point2buf(params.getGroup(), params.getH(), POINT_CONVERSION_COMPRESSED, &data[1], ctx);
    length[2] = EC_POINT_point2buf(params.getGroup(), params.getY1(), POINT_CONVERSION_COMPRESSED, &data[2], ctx);
    length[3] = EC_POINT_point2buf(params.getGroup(), params.getY2(), POINT_CONVERSION_COMPRESSED, &data[3], ctx);
    length[4] = EC_POINT_point2buf(params.getGroup(), Msg.T1, POINT_CONVERSION_COMPRESSED, &data[4], ctx);
    length[5] = EC_POINT_point2buf(params.getGroup(), Msg.T2, POINT_CONVERSION_COMPRESSED, &data[5], ctx);

    unsigned char* md = nullptr;
    unsigned int md_length = 0;
    assert(HashEncode(params.HashName, data, 6, length, md, md_length) == 0);

    BN_bin2bn(md, md_length, challenge);

    return challenge;
}

}



#endif //SIGMAPROTOCOL_SIGMADLOGEQUALITY_CC