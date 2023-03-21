#include "DiffieHellmanTriple.h"

#include <cassert>

namespace yacl::crypto {

void DiffieHellmanTripleProverShort::Prove() {
  BN_CTX* ctx = BN_CTX_new();
  // Compute First Message
  // sample two random number in Z_q
  std::vector<BIGNUM*>& k = GetK();
  std::vector<const BIGNUM*>& x = GetX();
  SigmaProtocolResponseMsgShort& Msg = this->GetMsgReference();

  BN_rand_range(k[0], params_.p);
  BN_rand_range(k[1], params_.p);

  std::vector<EC_POINT*> T;
  T.emplace_back(EC_POINT_new(params_.group));
  T.emplace_back(EC_POINT_new(params_.group));
  T.emplace_back(EC_POINT_new(params_.group));

  // calculate T1,T2,T3
  EC_POINT_mul(params_.group, T[0], nullptr, params_.G[0], k[0], ctx);
  EC_POINT_mul(params_.group, T[1], nullptr, params_.G[0], k[1], ctx);
  EC_POINT_mul(params_.group, T[2], nullptr, params_.H[0], k[1], ctx);

  // Compute Second Message
  // s[0] = k[0] + c*x[0], s[1] = k[1] +c*x[1]
  BN_free(Msg.c);
  Msg.c = DiffieHellmanTripleGetChallenge(params_, T, ctx);
  BN_mod_mul(Msg.s[0], Msg.c, x[0], params_.p, ctx);
  BN_mod_add(Msg.s[0], Msg.s[0], k[0], params_.p, ctx);
  BN_mod_mul(Msg.s[1], Msg.c, x[1], params_.p, ctx);
  BN_mod_add(Msg.s[1], Msg.s[1], k[1], params_.p, ctx);

  BN_CTX_free(ctx);
  EC_POINT_free(T[0]);
  EC_POINT_free(T[1]);
  EC_POINT_free(T[2]);
}

void DiffieHellmanTripleProverBatch::Prove() {
  BN_CTX* ctx = BN_CTX_new();

  // Compute First Message
  // sample two random number in Z_q
  std::vector<BIGNUM*>& k = GetK();
  std::vector<const BIGNUM*>& x = GetX();
  SigmaProtocolResponseMsgBatch& Msg = this->GetMsgReference();

  BN_rand_range(k[0], params_.p);
  BN_rand_range(k[1], params_.p);

  // calculate T1,T2,T3
  EC_POINT_mul(params_.group, Msg.T[0], nullptr, params_.G[0], k[0], ctx);
  EC_POINT_mul(params_.group, Msg.T[1], nullptr, params_.G[0], k[1], ctx);
  EC_POINT_mul(params_.group, Msg.T[2], nullptr, params_.H[0], k[1], ctx);

  // Compute Second Message
  // s[0] = k[0] + c*x[0], s[1] = k[1] +c*x[1]
  BIGNUM* challenge = DiffieHellmanTripleGetChallenge(params_, Msg.T, ctx);
  BN_mod_mul(Msg.s[0], challenge, x[0], params_.p, ctx);
  BN_mod_add(Msg.s[0], Msg.s[0], k[0], params_.p, ctx);
  BN_mod_mul(Msg.s[1], challenge, x[1], params_.p, ctx);
  BN_mod_add(Msg.s[1], Msg.s[1], k[1], params_.p, ctx);

  BN_CTX_free(ctx);
  BN_free(challenge);
}

bool DiffieHellmanTripleVerifierShort::Verify() {
  BN_CTX* ctx = BN_CTX_new();
  SigmaProtocolResponseMsgShort& Msg = this->GetMsg();
  EC_POINT* tmp1 = EC_POINT_new(params_.group);
  int res = 0;
  std::vector<EC_POINT*> T;
  T.emplace_back(EC_POINT_new(params_.group));
  T.emplace_back(EC_POINT_new(params_.group));
  T.emplace_back(EC_POINT_new(params_.group));

  // 1) compute T[0] = s[0]*G[0] - c*H[0]
  EC_POINT_mul(params_.group, T[0], nullptr, params_.G[0], Msg.s[0], ctx);
  EC_POINT_mul(params_.group, tmp1, nullptr, params_.H[0], Msg.c, ctx);
  EC_POINT_invert(params_.group, tmp1, ctx);
  EC_POINT_add(params_.group, T[0], T[0], tmp1, ctx);

  // 2) compute T[1] = s[1]*G[0] - c*H[1]
  EC_POINT_mul(params_.group, T[1], nullptr, params_.G[0], Msg.s[1], ctx);
  EC_POINT_mul(params_.group, tmp1, nullptr, params_.H[1], Msg.c, ctx);
  EC_POINT_invert(params_.group, tmp1, ctx);
  EC_POINT_add(params_.group, T[1], T[1], tmp1, ctx);

  // 3) compute T[2] = s[1]*H[1] - c*H[2]
  EC_POINT_mul(params_.group, T[2], nullptr, params_.H[1], Msg.s[1], ctx);
  EC_POINT_mul(params_.group, tmp1, nullptr, params_.H[2], Msg.c, ctx);
  EC_POINT_invert(params_.group, tmp1, ctx);
  EC_POINT_add(params_.group, T[2], T[2], tmp1, ctx);

  // Compute the challenge hash(G, Y1, Y2, Y3, T1, T2, T3)
  BIGNUM* challenge = DiffieHellmanTripleGetChallenge(params_, T, ctx);
  res = BN_cmp(challenge, GetMsg().c);

  BN_free(challenge);
  EC_POINT_free(tmp1);
  BN_CTX_free(ctx);
  if (res == -1) throw std::invalid_argument("EC_POINT_cmp error.\n");

  return (res == 0);
}

bool DiffieHellmanTripleVerifierBatch::Verify() {
  BN_CTX* ctx = BN_CTX_new();
  SigmaProtocolResponseMsgBatch& Msg = this->GetMsg();
  EC_POINT* tmp1 = EC_POINT_new(params_.group);
  EC_POINT* tmp2 = EC_POINT_new(params_.group);
  int res = 0;
  int tmp = 0;

  // Compute the challenge hash(G, Y1, Y2, Y3, T1, T2, T3)
  BIGNUM* challenge = DiffieHellmanTripleGetChallenge(params_, Msg.T, ctx);

  // calculate
  EC_POINT_mul(params_.group, tmp1, nullptr, params_.G[0], Msg.s[0], ctx);
  EC_POINT_mul(params_.group, tmp2, nullptr, params_.H[0], challenge, ctx);
  EC_POINT_add(params_.group, tmp2, tmp2, Msg.T[0], ctx);
  if ((tmp = EC_POINT_cmp(params_.group, tmp1, tmp2, ctx)) == -1) goto END;

  res += tmp;

  EC_POINT_mul(params_.group, tmp1, nullptr, params_.G[0], Msg.s[1], ctx);
  EC_POINT_mul(params_.group, tmp2, nullptr, params_.H[1], challenge, ctx);
  EC_POINT_add(params_.group, tmp2, tmp2, Msg.T[1], ctx);
  if ((tmp = EC_POINT_cmp(params_.group, tmp1, tmp2, ctx)) == -1) goto END;

  res += tmp;

  EC_POINT_mul(params_.group, tmp1, nullptr, params_.H[0], Msg.s[1], ctx);
  EC_POINT_mul(params_.group, tmp2, nullptr, params_.H[2], challenge, ctx);
  EC_POINT_add(params_.group, tmp2, tmp2, Msg.T[2], ctx);
  if ((tmp = EC_POINT_cmp(params_.group, tmp1, tmp2, ctx)) == -1) goto END;

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
    const std::vector<EC_POINT*>& T, BN_CTX* ctx) {
  unsigned char* data[8];
  unsigned int length[8];
  BIGNUM* challenge = BN_new();

  length[0] = EC_POINT_point2buf(params.group, params.G[0],
                                 POINT_CONVERSION_COMPRESSED, &data[0], ctx);
  length[1] = EC_POINT_point2buf(params.group, params.H[0],
                                 POINT_CONVERSION_COMPRESSED, &data[1], ctx);
  length[2] = EC_POINT_point2buf(params.group, params.H[1],
                                 POINT_CONVERSION_COMPRESSED, &data[2], ctx);
  length[3] = EC_POINT_point2buf(params.group, params.H[2],
                                 POINT_CONVERSION_COMPRESSED, &data[3], ctx);
  length[4] = EC_POINT_point2buf(params.group, T[0],
                                 POINT_CONVERSION_COMPRESSED, &data[4], ctx);
  length[5] = EC_POINT_point2buf(params.group, T[1],
                                 POINT_CONVERSION_COMPRESSED, &data[5], ctx);
  length[6] = EC_POINT_point2buf(params.group, T[2],
                                 POINT_CONVERSION_COMPRESSED, &data[6], ctx);

  unsigned char* md = nullptr;
  unsigned int md_length = 0;
  assert(HashEncode(params.hashname, data, 7, length, md, md_length) == 0);
  BN_bin2bn(md, md_length, challenge);

  return challenge;
}

}  // namespace yacl::crypto