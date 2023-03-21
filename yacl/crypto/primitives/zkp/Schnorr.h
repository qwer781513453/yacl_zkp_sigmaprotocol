#ifndef SIGMAPROTOCOL_SCHNORR_H
#define SIGMAPROTOCOL_SCHNORR_H

// Schnorr protcol: for a given generator H, group element Z,
// Prover wants to prove that he/she knows witness x that satisfies x*H = Z

#include "SigmaProtocol.h"
namespace yacl::crypto {

struct SchnorrCommonInput : public SigmaProtocolCommonInput {
  SchnorrCommonInput(const EC_GROUP* group, EC_POINT* G, EC_POINT* H,
                     const char* hashname = "sha256")
      : SigmaProtocolCommonInput(group, 1, 1, hashname) {
    this->G.emplace_back(G);
    this->H.emplace_back(H);
  }
};

class SchnorrProverShort : public SigmaProtocolProverShort {
 public:
  SchnorrProverShort(const SchnorrCommonInput& params, const BIGNUM* x)
      : params_(params), SigmaProtocolProverShort(1, 1, 1) {
    GetX()[0] = x;
  }

  void Prove() override;

 private:
  const SchnorrCommonInput& params_;
};

class SchnorrProverBatch : public SigmaProtocolProverBatch {
 public:
  SchnorrProverBatch(const SchnorrCommonInput& params, const BIGNUM* x)
      : params_(params), SigmaProtocolProverBatch(params.group, 1, 1, 1, 1) {
    GetX()[0] = x;
  }

  void Prove() override;

 private:
  const SchnorrCommonInput& params_;
};

class SchnorrVerifierShort : public SigmaProtocolVerifierShort {
 public:
  SchnorrVerifierShort(const SchnorrCommonInput& params,
                       const SigmaProtocolResponseMsgShort& msg)
      : params_(params), SigmaProtocolVerifierShort(msg) {}

  bool Verify() override;

 private:
  const SchnorrCommonInput& params_;
};

class SchnorrVerifierBatch : public SigmaProtocolVerifierBatch {
 public:
  SchnorrVerifierBatch(const SchnorrCommonInput& params,
                       const SigmaProtocolResponseMsgBatch& msg)
      : params_(params), SigmaProtocolVerifierBatch(msg) {}

  bool Verify() override;

 private:
  const SchnorrCommonInput& params_;
};

BIGNUM* SchnorrGetChallenge(const SchnorrCommonInput& params, const EC_POINT* T,
                            BN_CTX* ctx);

}  // namespace yacl::crypto

#endif  // SIGMAPROTOCOL_SCHNORR_H
