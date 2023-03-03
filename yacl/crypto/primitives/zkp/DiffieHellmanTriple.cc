#include "DiffieHellmanTriple.h"

#include <cassert>

namespace yacl::crypto {

DiffieHellmanTripleMessage::DiffieHellmanTripleMessage(
    const EC_GROUP* Group, const EC_POINT* T1, const EC_POINT* T2,
    const EC_POINT* T3, const BIGNUM* s1, const BIGNUM* s2)
    : Group(Group),
      T1(EC_POINT_new(Group)),
      T2(EC_POINT_new(Group)),
      T3(EC_POINT_new(Group)),
      s1(BN_new()),
      s2(BN_new()) {
  EC_POINT_copy(this->T1, T1);
  EC_POINT_copy(this->T2, T2);
  EC_POINT_copy(this->T3, T3);
  BN_copy(this->s1, s1);
  BN_copy(this->s2, s2);
}

DiffieHellmanTripleMessage::DiffieHellmanTripleMessage(
    const DiffieHellmanTripleMessage& Msg)
    : Group(Msg.Group),
      T1(EC_POINT_new(Group)),
      T2(EC_POINT_new(Group)),
      T3(EC_POINT_new(Group)),
      s1(BN_new()),
      s2(BN_new()) {
  EC_POINT_copy(this->T1, Msg.T1);
  EC_POINT_copy(this->T2, Msg.T2);
  EC_POINT_copy(this->T3, Msg.T3);
  BN_copy(this->s1, Msg.s1);
  BN_copy(this->s2, Msg.s2);
}

void DiffieHellmanTripleProver::ComputeFirstMessage() {
  BN_CTX* ctx = BN_CTX_new();
  // sample random elements
  BN_rand_range(r1, params.getP());
  BN_rand_range(r2, params.getP());

  // calculate T1,T2,T3
  EC_POINT_mul(params.getGroup(), Msg.T1, nullptr, params.getG(), r1, ctx);
  EC_POINT_mul(params.getGroup(), Msg.T2, nullptr, params.getG(), r2, ctx);
  EC_POINT_mul(params.getGroup(), Msg.T3, nullptr, params.getY1(), r2, ctx);

  flag1 = true;
  BN_CTX_free(ctx);
}

void DiffieHellmanTripleProver::ComputeSecondMessage() {
  if (!flag1)
    throw std::invalid_argument(
        "The first Message hasn't been calculate yet.Try to run "
        "ComputeFirstMessage().\n");
  BN_CTX* ctx = BN_CTX_new();

  // Compute the challenge hash(G, Y1, Y2, Y3, T1, T2, T3)

  BIGNUM* challenge = DiffieHellmanTripleGetChallenge(params, Msg, ctx);
  BN_mod_mul(Msg.s1, challenge, input.getW1(), params.getP(), ctx);
  BN_mod_add(Msg.s1, Msg.s1, r1, params.getP(), ctx);
  BN_mod_mul(Msg.s2, challenge, input.getW2(), params.getP(), ctx);
  BN_mod_add(Msg.s2, Msg.s2, r2, params.getP(), ctx);

  flag2 = true;
  BN_CTX_free(ctx);
  BN_free(challenge);
}

bool DiffieHellmanTripleVerifier::Verify() {
  BN_CTX* ctx = BN_CTX_new();
  int res = 0;
  int tmp = 0;

  // Compute the challenge hash(G, Y1, Y2, Y3, T1, T2, T3)
  BIGNUM* challenge = DiffieHellmanTripleGetChallenge(params, Msg, ctx);
  EC_POINT* tmp1 = EC_POINT_new(params.getGroup());
  EC_POINT* tmp2 = EC_POINT_new(params.getGroup());

  EC_POINT_mul(params.getGroup(), tmp1, nullptr, params.getG(), Msg.s1, ctx);
  EC_POINT_mul(params.getGroup(), tmp2, nullptr, params.getY1(), challenge,
               ctx);
  EC_POINT_add(params.getGroup(), tmp2, tmp2, Msg.T1, ctx);
  if ((tmp = EC_POINT_cmp(params.getGroup(), tmp1, tmp2, ctx)) == -1) goto END;

  res += tmp;

  EC_POINT_mul(params.getGroup(), tmp1, nullptr, params.getG(), Msg.s2, ctx);
  EC_POINT_mul(params.getGroup(), tmp2, nullptr, params.getY2(), challenge,
               ctx);
  EC_POINT_add(params.getGroup(), tmp2, tmp2, Msg.T2, ctx);
  if ((tmp = EC_POINT_cmp(params.getGroup(), tmp1, tmp2, ctx)) == -1) goto END;

  res += tmp;

  EC_POINT_mul(params.getGroup(), tmp1, nullptr, params.getY1(), Msg.s2, ctx);
  EC_POINT_mul(params.getGroup(), tmp2, nullptr, params.getY3(), challenge,
               ctx);
  EC_POINT_add(params.getGroup(), tmp2, tmp2, Msg.T3, ctx);
  if ((tmp = EC_POINT_cmp(params.getGroup(), tmp1, tmp2, ctx)) == -1) goto END;

  res += tmp;

END:
  BN_free(challenge);
  EC_POINT_free(tmp1);
  EC_POINT_free(tmp2);
  BN_CTX_free(ctx);
  if (tmp == -1) throw std::invalid_argument("EC_POINT_cmp error.\n");

  return (res == 0);
}

BIGNUM* DiffieHellmanTripleGetChallenge(
    const DiffieHellmanTripleCommonInput& params,
    const DiffieHellmanTripleMessage& Msg, BN_CTX* ctx) {
  unsigned char* data[8];
  unsigned int length[8];
  BIGNUM* challenge = BN_new();

  length[0] = EC_POINT_point2buf(params.getGroup(), params.getG(),
                                 POINT_CONVERSION_COMPRESSED, &data[0], ctx);
  length[1] = EC_POINT_point2buf(params.getGroup(), params.getY1(),
                                 POINT_CONVERSION_COMPRESSED, &data[1], ctx);
  length[2] = EC_POINT_point2buf(params.getGroup(), params.getY2(),
                                 POINT_CONVERSION_COMPRESSED, &data[2], ctx);
  length[3] = EC_POINT_point2buf(params.getGroup(), params.getY3(),
                                 POINT_CONVERSION_COMPRESSED, &data[3], ctx);
  length[4] = EC_POINT_point2buf(params.getGroup(), Msg.T1,
                                 POINT_CONVERSION_COMPRESSED, &data[4], ctx);
  length[5] = EC_POINT_point2buf(params.getGroup(), Msg.T2,
                                 POINT_CONVERSION_COMPRESSED, &data[5], ctx);
  length[6] = EC_POINT_point2buf(params.getGroup(), Msg.T3,
                                 POINT_CONVERSION_COMPRESSED, &data[6], ctx);

  unsigned char* md = nullptr;
  unsigned int md_length = 0;
  assert(HashEncode(params.HashName, data, 7, length, md, md_length) == 0);

  BN_bin2bn(md, md_length, challenge);

  return challenge;
}

}  // namespace yacl::crypto