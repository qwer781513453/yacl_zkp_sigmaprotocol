#ifndef SIGMAPROTOCOL_SIGMAPEDERSENCOMMITMENT_H
#define SIGMAPROTOCOL_SIGMAPEDERSENCOMMITMENT_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "SigmaProtocol.h"

// This protocol Prover proves that he knows openings of public Perdersen
// Commitment c Prover knows w1, w2 such that c = w1*G1 + w2*G2 mod p

namespace yacl::crypto {

/* input group, G, H, commitment */
struct PedersenCommitmentCommonInput : public SigmaProtocolCommonInput {
 public:
  PedersenCommitmentCommonInput(const EC_GROUP* Group, const EC_POINT* G1,
                                const EC_POINT* G2, const EC_POINT* Commitment,
                                const char* hashname = "sha256")
      : SigmaProtocolCommonInput(group, 2, 1, hashname) {
    this->G.emplace_back(G1);
    this->G.emplace_back(G2);
    this->H.emplace_back(Commitment);
  }
};

class PedersenCommitmentProverShort : public SigmaProtocolProverShort {
 public:
  PedersenCommitmentProverShort(const PedersenCommitmentCommonInput& params,
                                const BIGNUM* x1, const BIGNUM* x2)
      : params_(params_), SigmaProtocolProverShort(2, 2, 2) {
    GetX()[0] = x1;
    GetX()[1] = x2;
  }

  void Prove() override;

 private:
  const PedersenCommitmentCommonInput& params_;
};

class PedersenCommitmentProverBatch : public SigmaProtocolProverBatch {
 public:
  PedersenCommitmentProverBatch(const PedersenCommitmentCommonInput& params,
                                const BIGNUM* x1, const BIGNUM* x2)
      : params_(params_), SigmaProtocolProverBatch(params_.group, 2, 2, 2, 1) {
    GetX()[0] = x1;
    GetX()[1] = x2;
  }

  void Prove() override;

 private:
  const PedersenCommitmentCommonInput& params_;
};

class PedersemCommitmentVerifierShort : public SigmaProtocolVerifierShort {
 public:
  PedersemCommitmentVerifierShort(const PedersenCommitmentCommonInput& params,
                                  const SigmaProtocolResponseMsgShort& msg)
      : params_(params), SigmaProtocolVerifierShort(msg) {}

  bool Verify() override;

 private:
  const PedersenCommitmentCommonInput& params_;
};

class PedersemCommitmentVerifierBatch : public SigmaProtocolVerifierBatch {
 public:
  PedersemCommitmentVerifierBatch(const PedersenCommitmentCommonInput& params,
                                  const SigmaProtocolResponseMsgBatch& msg)
      : params_(params), SigmaProtocolVerifierBatch(msg) {}

  bool Verify() override;

 private:
  const PedersenCommitmentCommonInput& params_;
};

BIGNUM* PedersenCommitmentOpenGetChallenge(
    const PedersenCommitmentCommonInput& params, const EC_POINT* T,
    BN_CTX* ctx);

}  // namespace yacl::crypto

#endif  // SIGMAPROTOCOL_SIGMAPEDERSENCOMMITMENT_H
