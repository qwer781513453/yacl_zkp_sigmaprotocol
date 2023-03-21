#include "Schnorr.h"

#include <cassert>

namespace yacl::crypto {

void SchnorrProverShort::Prove() {
  BN_CTX* ctx = BN_CTX_new();
  // sample a random number k in Z_p
  GetK().emplace_back(BN_new());
  std::vector<BIGNUM*>& k = GetK();
  EC_POINT* T = EC_POINT_new(params_.group);
  BN_rand_range(k[0], params_.p);
  // compute FirstMessage T = random *G
  EC_POINT_mul(params_.group, T, nullptr, params_.G[0], k[0], ctx);

  // get challenge
  BN_free(GetMsgReference().c);  // mark may be wrong
  GetMsgReference().c = SchnorrGetChallenge(params_, T, ctx);

  // calculate s = w*e + random
  BN_mul(GetMsgReference().s[0], GetX()[0], GetMsgReference().c, ctx);
  BN_add(GetMsgReference().s[0], GetMsgReference().s[0], k[0]);

  EC_POINT_free(T);
  BN_CTX_free(ctx);
}

void SchnorrProverBatch::Prove() {
  BN_CTX* ctx = BN_CTX_new();
  // sample a random number k in Z_p
  GetK().emplace_back(BN_new());
  std::vector<BIGNUM*>& k = GetK();
  BN_rand_range(k[0], params_.p);
  // compute FirstMessage T = random *G
  EC_POINT_mul(params_.group, GetMsgReference().T[0], nullptr, params_.G[0],
               k[0], ctx);

  // get challenge
  BIGNUM* challenge = SchnorrGetChallenge(params_, GetMsgReference().T[0], ctx);

  // calculate r = w*e + random
  BN_mul(GetMsgReference().s[0], GetX()[0], challenge, ctx);
  BN_add(GetMsgReference().s[0], GetMsgReference().s[0], k[0]);

  BN_CTX_free(ctx);
  BN_free(challenge);
}

bool SchnorrVerifierShort::Verify() {
  BN_CTX* ctx = BN_CTX_new();
  int res;

  // calculate the commitmetn T = s*G - c*H
  EC_POINT* T = EC_POINT_new(params_.group);
  EC_POINT* tmp = EC_POINT_new(params_.group);
  EC_POINT_mul(params_.group, T, nullptr, params_.G[0], GetMsg().s[0], ctx);
  EC_POINT_mul(params_.group, tmp, nullptr, params_.H[0], GetMsg().c, ctx);
  EC_POINT_invert(params_.group, tmp, ctx);
  EC_POINT_add(params_.group, T, T, tmp, ctx);

  BIGNUM* challenge = SchnorrGetChallenge(params_, T, ctx);
  res = BN_cmp(challenge, GetMsg().c);

  EC_POINT_free(T);
  EC_POINT_free(tmp);
  if (res == -1) throw std::invalid_argument("EC_POINT_cmp error.\n");

  return (res == 0);
}

bool SchnorrVerifierBatch::Verify() {
  // calculate G^Y1
  BN_CTX* ctx = BN_CTX_new();
  int res;

  EC_POINT* tmp1 = EC_POINT_new(params_.group);
  EC_POINT* tmp2 = EC_POINT_new(params_.group);

  // get challenge Hash(G,H,T)
  BIGNUM* challenge = SchnorrGetChallenge(params_, GetMsg().T[0], ctx);

  EC_POINT_mul(params_.group, tmp1, nullptr, params_.G[0], GetMsg().s[0],
               ctx);  // tmp1 = r*G

  EC_POINT_mul(params_.group, tmp2, nullptr, params_.H[0], challenge, ctx);
  EC_POINT_add(params_.group, tmp2, tmp2, GetMsg().T[0],
               ctx);  // tmp2 = c*H + T

  res = EC_POINT_cmp(params_.group, tmp1, tmp2, ctx);
  BN_CTX_free(ctx);
  EC_POINT_free(tmp1);
  EC_POINT_free(tmp2);
  BN_free(challenge);

  if (res == -1) throw std::invalid_argument("EC_POINT_cmp error.\n");

  return (res == 0);
}

// compute the hash(G,H,T)
BIGNUM* SchnorrGetChallenge(const SchnorrCommonInput& params_,
                            const EC_POINT* T, BN_CTX* ctx) {
  unsigned char* data[4];
  unsigned int length[4];
  BIGNUM* challenge = BN_new();

  length[0] = EC_POINT_point2buf(params_.group, params_.G[0],
                                 POINT_CONVERSION_COMPRESSED, &data[0], ctx);
  length[1] = EC_POINT_point2buf(params_.group, params_.H[0],
                                 POINT_CONVERSION_COMPRESSED, &data[1], ctx);
  length[2] = EC_POINT_point2buf(params_.group, T, POINT_CONVERSION_COMPRESSED,
                                 &data[2], ctx);

  unsigned char* md = nullptr;
  unsigned int md_length = 0;
  assert(HashEncode(params_.hashname, data, 3, length, md, md_length) == 0);

  BN_bin2bn(md, md_length, challenge);
  return challenge;
}

}  // namespace yacl::crypto
