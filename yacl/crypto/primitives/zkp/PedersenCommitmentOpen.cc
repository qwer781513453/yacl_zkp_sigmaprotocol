#include "PedersenCommitmentOpen.h"

#include <cassert>

#include "cstring"

namespace yacl::crypto {

void PedersenCommitmentProver::ComputeFirstMessage() {
  BN_CTX* ctx = BN_CTX_new();
  EC_POINT* tmp = EC_POINT_new(params.getGroup());
  // sample a random number r1,r2 in Z_q
  BN_rand_range(r1, params.getP());
  BN_rand_range(r2, params.getP());

  // calculate T = Y1*G + r2*H
  EC_POINT_mul(params.getGroup(), Msg.T, nullptr, params.getG(), r1, ctx);
  EC_POINT_mul(params.getGroup(), tmp, nullptr, params.getH(), r2, ctx);
  EC_POINT_add(params.getGroup(), Msg.T, Msg.T, tmp, ctx);

  flag1 = true;
  BN_CTX_free(ctx);
  EC_POINT_free(tmp);
}

void PedersenCommitmentProver::ComputeSecondMessage() {
  if (!flag1)
    throw std::invalid_argument(
        "The first Message hasn't been calculate yet.Try to run "
        "ComputeFirstMessage().\n");
  BN_CTX* ctx = BN_CTX_new();

  // compute the challenge hash(G,H,Commitment,T)
  BIGNUM* challenge = PedersenCommitmentOpenGetChallenge(params, Msg, ctx);

  // compute s1 = Y1+ex, s2 = r2+er
  BN_mul(Msg.s1, challenge, input.getW1(), ctx);
  BN_add(Msg.s1, Msg.s1, r1);

  BN_mul(Msg.s2, challenge, input.getW2(), ctx);
  BN_add(Msg.s2, Msg.s2, r2);

  flag2 = true;
  BN_CTX_free(ctx);
}

bool PedersemCommitmentVerifier::Verify() {
  BN_CTX* ctx = BN_CTX_new();

  // compute the challenge hash(G,H,Commitment,T)
  BIGNUM* challenge = PedersenCommitmentOpenGetChallenge(params, Msg, ctx);

  // check G*s1 + H*s2 = T+c*e mod P
  EC_POINT* tmp1 = EC_POINT_new(params.getGroup());
  EC_POINT* tmp2 = EC_POINT_new(params.getGroup());

  EC_POINT_mul(params.getGroup(), tmp1, nullptr, params.getH(), Msg.s2,
               ctx);  // H*s2
  EC_POINT_mul(params.getGroup(), tmp2, nullptr, params.getG(), Msg.s1,
               ctx);  // G*s1
  EC_POINT_add(params.getGroup(), tmp1, tmp1, tmp2, ctx);
  EC_POINT_mul(params.getGroup(), tmp2, nullptr, params.getCommitment(),
               challenge, ctx);  // c*e
  EC_POINT_add(params.getGroup(), tmp2, tmp2, Msg.T, ctx);

  int res = EC_POINT_cmp(params.getGroup(), tmp1, tmp2, ctx);

  BN_CTX_free(ctx);
  EC_POINT_free(tmp2);
  EC_POINT_free(tmp1);
  BN_free(challenge);

  if (res == -1) throw std::invalid_argument("EC_POINT_cmp error.\n");

  return (res == 0);
}

// compute the challenge hash(G,H,Commitment,T)
BIGNUM* PedersenCommitmentOpenGetChallenge(
    const PedersenCommitmentCommonInput& params,
    const PedersenCommitmentMessage& Msg, BN_CTX* ctx) {
  unsigned char* data[5];
  unsigned int length[5];
  BIGNUM* challenge = BN_new();

  length[0] = EC_POINT_point2buf(params.getGroup(), params.getG(),
                                 POINT_CONVERSION_COMPRESSED, &data[0], ctx);
  length[1] = EC_POINT_point2buf(params.getGroup(), params.getH(),
                                 POINT_CONVERSION_COMPRESSED, &data[1], ctx);
  length[2] = EC_POINT_point2buf(params.getGroup(), params.getCommitment(),
                                 POINT_CONVERSION_COMPRESSED, &data[2], ctx);
  length[3] = EC_POINT_point2buf(params.getGroup(), Msg.T,
                                 POINT_CONVERSION_COMPRESSED, &data[2], ctx);

  unsigned char* md = nullptr;
  unsigned int md_length = 0;
  assert(HashEncode(params.HashName, data, 4, length, md, md_length) == 0);

  BN_bin2bn(md, md_length, challenge);

  return challenge;
}

}  // namespace yacl::crypto
