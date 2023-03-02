#include "Schnorr.h"
#include <cassert>

namespace yacl::crypto{

void SchnorrProver::ComputeFirstMessage()
{
    BN_CTX* ctx = BN_CTX_new();
    // sample a random number r in Z_p
    BN_rand_range(r, params.getP());
    // compute FirstMessage T = r*G
    EC_POINT_mul(params.getGroup(), Msg.T, nullptr, params.getG(), r, ctx);

    flag1 = true;

    BN_CTX_free(ctx);
}


void SchnorrProver::ComputeSecondMessage()
{
    if(!flag1)
        throw std::invalid_argument("The first Message hasn't been calculate yet.Try to run ComputeFirstMessage().\n");
    BN_CTX * ctx = BN_CTX_new();
    // get challenge
    BIGNUM* challenge = SchnorrGetChallenge(params, Msg, ctx);

    // calculate s = w*e + r
    BN_mul(Msg.s, input.getW(), challenge, ctx);
    BN_add(Msg.s, Msg.s, r);

    flag2 = true;
    BN_free(challenge);
    BN_CTX_free(ctx);
}


bool SchnorrVerifier::Verify()
{
    //calculate G^Y1
    BN_CTX * ctx = BN_CTX_new();
    int res;

    EC_POINT* tmp1 = EC_POINT_new(params.getGroup());
    EC_POINT* tmp2 = EC_POINT_new(params.getGroup());

    // get challenge Hash(G,H,T)
    BIGNUM* challenge = SchnorrGetChallenge(params, Msg, ctx);

    EC_POINT_mul(params.getGroup(), tmp1, nullptr, params.getG(), Msg.s, ctx);  // tmp1 = s*G

    EC_POINT_mul(params.getGroup(), tmp2, nullptr, params.getH(), challenge, ctx);
    EC_POINT_add(params.getGroup(), tmp2, tmp2, Msg.T, ctx); // tmp2 = c*H + T

    res = EC_POINT_cmp(params.getGroup(), tmp1, tmp2, ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(tmp1);
    EC_POINT_free(tmp2);
    BN_free(challenge);

    if(res == -1)
        throw std::invalid_argument("EC_POINT_cmp error.\n");

    return (res == 0);
}

// compute the hash(G,H,T)
BIGNUM* SchnorrGetChallenge(const SchnorrCommonInput &params, const SchnorrMessage &Msg, BN_CTX* ctx)
{
    unsigned char* data[4];
    unsigned int length[4];
    BIGNUM* challenge = BN_new();

    length[0] = EC_POINT_point2buf(params.getGroup(), params.getG(), POINT_CONVERSION_COMPRESSED, &data[0], ctx);
    length[1] = EC_POINT_point2buf(params.getGroup(), params.getH(), POINT_CONVERSION_COMPRESSED, &data[1], ctx);
    length[2] = EC_POINT_point2buf(params.getGroup(), Msg.T, POINT_CONVERSION_COMPRESSED, &data[2], ctx);

    unsigned char* md = nullptr;
    unsigned int md_length = 0;
    assert(HashEncode(params.HashName, data, 3, length, md, md_length) == 0);

    BN_bin2bn(md, md_length, challenge);
    return challenge;
}


}

