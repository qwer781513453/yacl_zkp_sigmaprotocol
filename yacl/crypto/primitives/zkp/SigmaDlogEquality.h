//
// Created by wx on 23-1-4.
//

#ifndef SIGMAPROTOCOL_SIGMADLOGEQUALITY_H
#define SIGMAPROTOCOL_SIGMADLOGEQUALITY_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "SigmaProtocol.h"

namespace yacl::crypto {

class DlogEqualityCommonInput : public SigmaProtocolCommonInput {
 public:
  DlogEqualityCommonInput(const EC_GROUP* Group, const EC_POINT* g,
                          const EC_POINT* h, const EC_POINT* y,
                          const EC_POINT* z, const char* HashName = "sha256")
      : Group(Group),
        G(g),
        H(h),
        Y1(y),
        Y2(z),
        p(BN_new()),
        SigmaProtocolCommonInput(HashName) {
    p = EC_GROUP_get0_order(Group);
  };

  const EC_GROUP* getGroup() const { return this->Group; }

  const EC_POINT* getG() const { return this->G; }

  const EC_POINT* getH() const { return this->H; }

  const EC_POINT* getY1() const { return this->Y1; }

  const EC_POINT* getY2() const { return this->Y2; }

  const BIGNUM* getP() const { return this->p; }

 private:
  const EC_GROUP* Group;

  const EC_POINT* G;   // generator of Z_q
  const EC_POINT* H;   // generator of Z_q
  const EC_POINT* Y1;  // w*G = Y1
  const EC_POINT* Y2;  // w*H = Y2

  const BIGNUM* p;
};

class DlogEqualityProverInput : public SigmaProtocolProverInput {
 public:
  explicit DlogEqualityProverInput(BIGNUM* w) : w(w){};

  const BIGNUM* getW() const { return this->w; }

 private:
  BIGNUM* w;  // witness w \in Z_q
};

class DlogEqualityMessage : public SigmaProtocolResponseMessage {
 public:
  explicit DlogEqualityMessage(const EC_GROUP* Group)
      : Group(Group),
        T1(EC_POINT_new(Group)),
        T2(EC_POINT_new(Group)),
        s(BN_new()) {}

  DlogEqualityMessage(const EC_GROUP* Group, const EC_POINT* T1,
                      const EC_POINT* T2, BIGNUM* s)
      : Group(Group),
        T1(EC_POINT_new(Group)),
        T2(EC_POINT_new(Group)),
        s(BN_new()) {
    EC_POINT_copy(this->T1, T1);
    EC_POINT_copy(this->T2, T2);
    BN_copy(this->s, s);
  }

  DlogEqualityMessage(const DlogEqualityMessage& Msg)
      : Group(Msg.Group),
        T1(EC_POINT_new(Group)),
        T2(EC_POINT_new(Group)),
        s(BN_new()) {
    EC_POINT_copy(this->T1, Msg.T1);
    EC_POINT_copy(this->T2, Msg.T2);
    BN_copy(this->s, Msg.s);
  }

  ~DlogEqualityMessage() {
    EC_POINT_free(T1);
    EC_POINT_free(T2);
    BN_free(s);
  }

  const EC_GROUP* Group;

  EC_POINT *T1, *T2;  // FirstMessage T1 = w2*G, T2 = w2*H

  BIGNUM* s;  // SecondMessage r2 = w2+cw
};

class DlogEqualityProver : public SigmaProtocolProver {
 public:
  DlogEqualityProver(const DlogEqualityCommonInput& params,
                     const DlogEqualityProverInput& input)
      : params(params),
        input(input),
        r(BN_new()),
        Msg(params.getGroup()),
        flag1(0),
        flag2(0) {}

  void ComputeFirstMessage() override;

  void ComputeSecondMessage() override;

  DlogEqualityMessage getMsg() {
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
  BIGNUM* r;  // random element

  const DlogEqualityCommonInput& params;

  const DlogEqualityProverInput& input;

  bool flag1, flag2;

  DlogEqualityMessage Msg;
};

class DlogEqualityVerifier : public SigmaProtocolVerifier {
 public:
  DlogEqualityVerifier(const DlogEqualityCommonInput& params,
                       const DlogEqualityMessage& Msg)
      : params(params), Msg(Msg) {}

  bool Verify() override;

 private:
  const DlogEqualityCommonInput& params;

  const DlogEqualityMessage& Msg;
};

BIGNUM* DlogEqualityGetChallenge(const DlogEqualityCommonInput& params,
                                 const DlogEqualityMessage& Msg, BN_CTX* ctx);

}  // namespace yacl::crypto

#endif  // SIGMAPROTOCOL_SIGMADLOGEQUALITY_H
