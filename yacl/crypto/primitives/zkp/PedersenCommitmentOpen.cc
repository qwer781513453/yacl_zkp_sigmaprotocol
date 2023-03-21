#include "PedersenCommitmentOpen.h"

#include <cassert>

#include "cstring"

namespace yacl::crypto {

void PedersenCommitmentProverShort::Prove() {
  BN_CTX* ctx = BN_CTX_new();
  EC_POINT* tmp = EC_POINT_new(params_.group);

  // Compute First Message T = Y1*G + r2*H
  // sample two random number in Z_q
  std::vector<BIGNUM*>& k = GetK();
  std::vector<const BIGNUM*>& x = GetX();
  SigmaProtocolResponseMsgShort& Msg = this->GetMsgReference();

  EC_POINT* T = EC_POINT_new(params_.group);

  BN_rand_range(k[0], params_.p);
  BN_rand_range(k[1], params_.p);

  EC_POINT_mul(params_.group, T, nullptr, params_.G[0], k[0], ctx);
  EC_POINT_mul(params_.group, tmp, nullptr, params_.G[1], k[1], ctx);
  EC_POINT_add(params_.group, T, T, tmp, ctx);

  // Compute Second Message s1 = Y1+ex, s2 = r2+er
  // compute the challenge hash(G,H,Commitment,T)
  BN_free(Msg.c);
  Msg.c = PedersenCommitmentOpenGetChallenge(params_, T, ctx);

  // compute s1 = Y1+ex, s2 = r2+er
  BN_mul(Msg.s[0], Msg.c, x[0], ctx);
  BN_add(Msg.s[0], Msg.s[0], k[0]);

  BN_mul(Msg.s[1], Msg.c, x[1], ctx);
  BN_add(Msg.s[1], Msg.s[1], k[1]);

  EC_POINT_free(T);
  BN_CTX_free(ctx);
  EC_POINT_free(tmp);
}

void PedersenCommitmentProverBatch::Prove() {
  BN_CTX* ctx = BN_CTX_new();
  EC_POINT* tmp = EC_POINT_new(params_.group);

  // Compute First Message T = Y1*G + r2*H
  // sample two random number in Z_q
  std::vector<BIGNUM*>& k = GetK();
  std::vector<const BIGNUM*>& x = GetX();
  SigmaProtocolResponseMsgBatch& Msg = this->GetMsgReference();

  BN_rand_range(k[0], params_.p);
  BN_rand_range(k[1], params_.p);

  EC_POINT_mul(params_.group, Msg.T[0], nullptr, params_.G[0], k[0], ctx);
  if (params_.G[1] == nullptr) printf("errorr");
  EC_POINT_mul(params_.group, tmp, nullptr, params_.G[1], k[1], ctx);
  EC_POINT_add(params_.group, Msg.T[0], Msg.T[0], tmp, ctx);

  // Compute Second Message s1 = Y1+ex, s2 = r2+er
  // compute the challenge hash(G,H,Commitment,T)
  BIGNUM* challenge =
      PedersenCommitmentOpenGetChallenge(params_, Msg.T[0], ctx);

  // compute s1 = Y1+ex, s2 = r2+er
  BN_mul(Msg.s[0], challenge, x[0], ctx);
  BN_add(Msg.s[0], Msg.s[0], k[0]);

  BN_mul(Msg.s[1], challenge, x[1], ctx);
  BN_add(Msg.s[1], Msg.s[1], k[1]);

  BN_CTX_free(ctx);
  EC_POINT_free(tmp);
  BN_free(challenge);
}

bool PedersemCommitmentVerifierShort::Verify() {
  BN_CTX* ctx = BN_CTX_new();
  int res = 0;

  EC_POINT* tmp = EC_POINT_new(params_.group);

  EC_POINT* T = EC_POINT_new(params_.group);

  // T = (s[0]*G[0]+ s[1]*G[1]) - c*H[0]
  EC_POINT_mul(params_.group, T, nullptr, params_.G[0], GetMsg().s[0], ctx);
  EC_POINT_mul(params_.group, tmp, nullptr, params_.G[1], GetMsg().s[1], ctx);
  EC_POINT_add(params_.group, T, T, tmp, ctx);

  EC_POINT_mul(params_.group, tmp, nullptr, params_.H[0], GetMsg().c, ctx);
  EC_POINT_invert(params_.group, tmp, ctx);
  EC_POINT_add(params_.group, T, T, tmp, ctx);

  BIGNUM* challenge = PedersenCommitmentOpenGetChallenge(params_, T, ctx);
  res = BN_cmp(challenge, GetMsg().c);

  BN_CTX_free(ctx);
  EC_POINT_free(T);
  EC_POINT_free(tmp);
  BN_free(challenge);
  if (res == -1) throw std::invalid_argument("EC_POINT_cmp error.\n");

  return (res == 0);
}

bool PedersemCommitmentVerifierBatch::Verify() {
  BN_CTX* ctx = BN_CTX_new();
  SigmaProtocolResponseMsgBatch& Msg = this->GetMsg();

  // compute the challenge hash(G,H,Commitment,T)
  BIGNUM* challenge =
      PedersenCommitmentOpenGetChallenge(params_, Msg.T[0], ctx);

  // check G1*s1 + G2*s2 = T+c*e mod P
  EC_POINT* tmp1 = EC_POINT_new(params_.group);
  EC_POINT* tmp2 = EC_POINT_new(params_.group);

  EC_POINT_mul(params_.group, tmp2, nullptr, params_.G[0], Msg.s[0],
               ctx);  // G1*s1
  EC_POINT_mul(params_.group, tmp1, nullptr, params_.G[1], Msg.s[1],
               ctx);  // G2*s2

  EC_POINT_add(params_.group, tmp1, tmp1, tmp2, ctx);
  EC_POINT_mul(params_.group, tmp2, nullptr, params_.H[0], challenge,
               ctx);  // c*e
  EC_POINT_add(params_.group, tmp2, tmp2, Msg.T[0], ctx);

  int res = EC_POINT_cmp(params_.group, tmp1, tmp2, ctx);

  BN_CTX_free(ctx);
  EC_POINT_free(tmp2);
  EC_POINT_free(tmp1);
  BN_free(challenge);

  if (res == -1) throw std::invalid_argument("EC_POINT_cmp error.\n");

  return (res == 0);
}

// compute the challenge hash(G,H,Commitment,T)
BIGNUM* PedersenCommitmentOpenGetChallenge(
    const PedersenCommitmentCommonInput& params, const EC_POINT* T,
    BN_CTX* ctx) {
  unsigned char* data[5];
  unsigned int length[5];
  BIGNUM* challenge = BN_new();

  length[0] = EC_POINT_point2buf(params.group, params.G[0],
                                 POINT_CONVERSION_COMPRESSED, &data[0], ctx);
  length[1] = EC_POINT_point2buf(params.group, params.G[1],
                                 POINT_CONVERSION_COMPRESSED, &data[1], ctx);
  length[2] = EC_POINT_point2buf(params.group, params.H[0],
                                 POINT_CONVERSION_COMPRESSED, &data[2], ctx);
  length[3] = EC_POINT_point2buf(params.group, T, POINT_CONVERSION_COMPRESSED,
                                 &data[3], ctx);

  unsigned char* md = nullptr;
  unsigned int md_length = 0;
  assert(HashEncode(params.hashname, data, 4, length, md, md_length) == 0);

  BN_bin2bn(md, md_length, challenge);

  return challenge;
}

}  // namespace yacl::crypto
