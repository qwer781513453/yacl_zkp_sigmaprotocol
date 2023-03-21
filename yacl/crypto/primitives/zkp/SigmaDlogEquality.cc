#include "SigmaDlogEquality.h"

#include <cassert>

namespace yacl::crypto {

void DlogEqualityProverShort::Prove() {
  BN_CTX* ctx = BN_CTX_new();
  SigmaProtocolResponseMsgShort& Msg = GetMsgReference();
  // sample a random number w2 in Z_p
  BN_rand_range(GetK()[0], params_.p);
  // compute FirstMessage: two commitments
  std::vector<EC_POINT*> T;
  T.emplace_back(EC_POINT_new(params_.group));
  T.emplace_back(EC_POINT_new(params_.group));
  EC_POINT_mul(params_.group, T[0], nullptr, params_.G[0], GetK()[0], ctx);
  EC_POINT_mul(params_.group, T[1], nullptr, params_.G[1], GetK()[0], ctx);

  // compute SecondMessage
  // compute the challenge hash(G, H, Y1, Y2, t1, t2)
  BN_free(Msg.c);
  Msg.c = DlogEqualityGetChallenge(params_, T, ctx);

  BN_mod_mul(Msg.s[0], Msg.c, GetX()[0], params_.p, ctx);
  BN_mod_add(Msg.s[0], Msg.s[0], GetK()[0], params_.p, ctx);

  EC_POINT_free(T[0]);
  EC_POINT_free(T[1]);
  BN_CTX_free(ctx);
}

void DlogEqualityProverBatch::Prove() {
  BN_CTX* ctx = BN_CTX_new();
  SigmaProtocolResponseMsgBatch& Msg = GetMsgReference();

  // sample a random number w2 in Z_p
  BN_rand_range(GetK()[0], params_.p);
  // compute FirstMessage: two commitments
  EC_POINT_mul(params_.group, Msg.T[0], nullptr, params_.G[0], GetK()[0], ctx);
  EC_POINT_mul(params_.group, Msg.T[1], nullptr, params_.G[1], GetK()[0], ctx);

  // compute SecondMessage
  // compute the challenge hash(G, H, Y1, Y2, t1, t2)
  BIGNUM* challenge = DlogEqualityGetChallenge(params_, Msg.T, ctx);

  BN_mod_mul(Msg.s[0], challenge, GetX()[0], params_.p, ctx);
  BN_mod_add(Msg.s[0], Msg.s[0], GetK()[0], params_.p, ctx);

  BN_CTX_free(ctx);
  BN_free(challenge);
}

bool DlogEqualityVerifierShort::Verify() {
  BN_CTX* ctx = BN_CTX_new();
  int res = 0;
  const SigmaProtocolResponseMsgShort& Msg = GetMsg();

  EC_POINT* tmp1 = EC_POINT_new(params_.group);

  std::vector<EC_POINT*> T;
  T.emplace_back(EC_POINT_new(params_.group));
  T.emplace_back(EC_POINT_new(params_.group));

  // 1)T1 = s[0]*G[0] - c*H[0]
  EC_POINT_mul(params_.group, T[0], nullptr, params_.G[0], Msg.s[0], ctx);
  EC_POINT_mul(params_.group, tmp1, nullptr, params_.H[0], Msg.c, ctx);
  EC_POINT_invert(params_.group, tmp1, ctx);
  EC_POINT_add(params_.group, T[0], T[0], tmp1, ctx);

  // 2)T2 = s[0]*G[1] - c*H[1]
  EC_POINT_mul(params_.group, T[1], nullptr, params_.G[1], Msg.s[0], ctx);
  EC_POINT_mul(params_.group, tmp1, nullptr, params_.H[1], Msg.c, ctx);
  EC_POINT_invert(params_.group, tmp1, ctx);
  EC_POINT_add(params_.group, T[1], T[1], tmp1, ctx);

  BIGNUM* challenge = DlogEqualityGetChallenge(params_, T, ctx);
  res = BN_cmp(challenge, Msg.c);

  BN_CTX_free(ctx);
  EC_POINT_free(tmp1);
  EC_POINT_free(T[0]);
  EC_POINT_free(T[1]);
  BN_free(challenge);
  if (res == -1) throw std::invalid_argument("EC_POINT_cmp error.\n");

  return (res == 0);
}

bool DlogEqualityVerifierBatch::Verify() {
  BN_CTX* ctx = BN_CTX_new();
  int res = 0;
  int tmp = 0;
  const SigmaProtocolResponseMsgBatch& Msg = GetMsg();

  BIGNUM* challenge = DlogEqualityGetChallenge(params_, Msg.T, ctx);

  // verify whether :
  EC_POINT* tmp1 = EC_POINT_new(params_.group);
  EC_POINT* tmp2 = EC_POINT_new(params_.group);

  // 1) G^r2 = Y1^c*t1
  EC_POINT_mul(params_.group, tmp1, nullptr, params_.G[0], Msg.s[0], ctx);
  EC_POINT_mul(params_.group, tmp2, nullptr, params_.H[0], challenge, ctx);
  EC_POINT_add(params_.group, tmp2, tmp2, Msg.T[0], ctx);
  if ((tmp = EC_POINT_cmp(params_.group, tmp1, tmp2, ctx) == -1)) goto END;
  res += tmp;

  // 2) H^r2 = Y2^c*t2
  EC_POINT_mul(params_.group, tmp1, nullptr, params_.G[1], Msg.s[0], ctx);
  EC_POINT_mul(params_.group, tmp2, nullptr, params_.H[1], challenge, ctx);
  EC_POINT_add(params_.group, tmp2, tmp2, Msg.T[1], ctx);
  if ((tmp = EC_POINT_cmp(params_.group, tmp1, tmp2, ctx) == -1)) goto END;
  res += tmp;

END:
  BN_CTX_free(ctx);
  EC_POINT_free(tmp2);
  EC_POINT_free(tmp1);
  BN_free(challenge);
  if (tmp == -1) throw std::invalid_argument("EC_POINT_cmp error.\n");

  return (res == 0);
}

// compute hash(G,H,Y1,Y2,T1,T2)
BIGNUM* DlogEqualityGetChallenge(const DlogEqualityCommonInput& params_,
                                 const std::vector<EC_POINT*> T, BN_CTX* ctx) {
  unsigned char* data[7];
  unsigned int length[7];
  BIGNUM* challenge = BN_new();

  length[0] = EC_POINT_point2buf(params_.group, params_.G[0],
                                 POINT_CONVERSION_COMPRESSED, &data[0], ctx);
  length[1] = EC_POINT_point2buf(params_.group, params_.G[1],
                                 POINT_CONVERSION_COMPRESSED, &data[1], ctx);
  length[2] = EC_POINT_point2buf(params_.group, params_.H[0],
                                 POINT_CONVERSION_COMPRESSED, &data[2], ctx);
  length[3] = EC_POINT_point2buf(params_.group, params_.H[1],
                                 POINT_CONVERSION_COMPRESSED, &data[3], ctx);
  length[4] = EC_POINT_point2buf(params_.group, T[0],
                                 POINT_CONVERSION_COMPRESSED, &data[4], ctx);
  length[5] = EC_POINT_point2buf(params_.group, T[1],
                                 POINT_CONVERSION_COMPRESSED, &data[5], ctx);

  unsigned char* md = nullptr;
  unsigned int md_length = 0;
  assert(HashEncode(params_.hashname, data, 6, length, md, md_length) == 0);

  BN_bin2bn(md, md_length, challenge);

  return challenge;
}

}  // namespace yacl::crypto
