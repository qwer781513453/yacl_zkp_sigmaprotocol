#ifndef SIGMAPROTOCOL_SIGMAPEDERSENCOMMITMENT_H
#define SIGMAPROTOCOL_SIGMAPEDERSENCOMMITMENT_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "SigmaProtocol.h"

// This protocol Prover proves that he knows openings of public Perdersen
// Commitment c Prover knows w, w2 such that c = G^w * H^w2 mod p

namespace yacl::crypto {

/* input group, G, H, commitment */
class PedersenCommitmentCommonInput : public SigmaProtocolCommonInput {
 public:
  PedersenCommitmentCommonInput(const EC_GROUP* Group, const EC_POINT* g,
                                const EC_POINT* h, const EC_POINT* Commitment,
                                const char* HashName = "sha256")
      : Group(Group),
        G(g),
        H(h),
        Commitment(Commitment),
        SigmaProtocolCommonInput(HashName) {
    this->p = EC_GROUP_get0_order(Group);
  }

  const EC_GROUP* getGroup() const { return this->Group; }

  const BIGNUM* getP() const { return this->p; }

  const EC_POINT* getG() const { return this->G; }

  const EC_POINT* getH() const { return this->H; }

  const EC_POINT* getCommitment() const { return this->Commitment; }

 private:
  const EC_GROUP* Group;  // the EC_GROUP

  const BIGNUM* p;

  const EC_POINT* G;  // generator

  const EC_POINT* H;  // generator

  const EC_POINT* Commitment;
};

class PedersenCommitmentProverInput : public SigmaProtocolProverInput {
 public:
  PedersenCommitmentProverInput() = default;

  PedersenCommitmentProverInput(const BIGNUM* x, const BIGNUM* r)
      : w1(x), w2(r) {}

  const BIGNUM* getW1() const { return w1; }

  const BIGNUM* getW2() const { return w2; }

 private:
  const BIGNUM* w1;

  const BIGNUM* w2;
};

class PedersenCommitmentMessage : public SigmaProtocolResponseMessage {
 public:
  explicit PedersenCommitmentMessage(const EC_GROUP* Group)
      : Group(Group), T(EC_POINT_new(Group)), s1(BN_new()), s2(BN_new()) {}

  PedersenCommitmentMessage(const EC_GROUP* Group, const EC_POINT* d,
                            const BIGNUM* u, const BIGNUM* v)
      : Group(Group), T(EC_POINT_new(Group)), s1(BN_new()), s2(BN_new()) {
    EC_POINT_copy(this->T, d);
    BN_copy(this->s1, u);
    BN_copy(this->s2, v);
  }

  PedersenCommitmentMessage(const PedersenCommitmentMessage& msg)
      : Group(msg.Group), T(EC_POINT_new(Group)), s1(BN_new()), s2(BN_new()) {
    EC_POINT_copy(this->T, msg.T);
    BN_copy(this->s1, msg.s1);
    BN_copy(this->s2, msg.s2);
  }

  ~PedersenCommitmentMessage() {
    BN_free(s1);
    BN_free(s2);
    EC_POINT_free(T);
  }

  const EC_GROUP* Group;

  EC_POINT* T;  // T = Y1*G + r2*H

  BIGNUM* s1;  // s1 = Y1+ex

  BIGNUM* s2;  // s2 = r2+er
};

class PedersenCommitmentProver : public SigmaProtocolProver {
 public:
  PedersenCommitmentProver(const PedersenCommitmentCommonInput& params,
                           const PedersenCommitmentProverInput& input)
      : params(params),
        input(input),
        Msg(params.getGroup()),
        r1(BN_new()),
        r2(BN_new()),
        flag1(0),
        flag2(0) {}

  void ComputeFirstMessage() override;

  void ComputeSecondMessage() override;

  PedersenCommitmentMessage getMsg() {
    if (!flag1)
      throw std::invalid_argument(
          "FirstMessage hasn't been calculated yet. Try to run "
          "ComputeFirstMessage()");
    if (!flag2)
      throw std::invalid_argument(
          "SecondMessage hasn't been calculated yet. Try to run "
          "ComputeSecondMessage()");
    return this->Msg;
  }

 private:
  BIGNUM* r1;
  BIGNUM* r2;

  PedersenCommitmentMessage Msg;

  const PedersenCommitmentCommonInput& params;

  const PedersenCommitmentProverInput& input;

  bool flag1, flag2;
};

class PedersemCommitmentVerifier : public SigmaProtocolVerifier {
 public:
  PedersemCommitmentVerifier(const PedersenCommitmentCommonInput& params,
                             const PedersenCommitmentMessage& Msg)
      : params(params), Msg(Msg) {}

  bool Verify() override;

 private:
  const PedersenCommitmentCommonInput& params;

  const PedersenCommitmentMessage& Msg;
};

BIGNUM* PedersenCommitmentOpenGetChallenge(
    const PedersenCommitmentCommonInput& params,
    const PedersenCommitmentMessage& Msg, BN_CTX* ctx);

}  // namespace yacl::crypto

#endif  // SIGMAPROTOCOL_SIGMAPEDERSENCOMMITMENT_H
