#ifndef SIGMAPROTOCOL_SIGMAPROTOCOL_H
#define SIGMAPROTOCOL_SIGMAPROTOCOL_H

// Implement UGZK protocol:
// let n be a positive integer and let i \in [1,n]. For a given vector {Z_i}_{i
// \in [1,n]}, the protocol is a proof of knowledge of a vector {[x_i]}_{i \in
// [1,n]} such that Z_i = [x_i]

#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdio>
#include <memory>
#include <stdexcept>
#include <vector>

#include "hash.h"

namespace yacl::crypto {
// SigmaprotocolCommoInput specifies the OneWayHomomorphism and hashname of
// practical protocol
struct SigmaProtocolCommonInput {
  SigmaProtocolCommonInput(const EC_GROUP* group, size_t G_size, size_t H_size,
                           const char* hashname)
      : group(group), hashname(hashname) {
    G.reserve(G_size);
    H.reserve(H_size);
    p = EC_GROUP_get0_order(group);
  }

  const EC_GROUP* group;
  const BIGNUM* p;
  std::vector<const EC_POINT*> G;  // public generators of group
  std::vector<const EC_POINT*> H;  // public group elements

  const char* hashname;
};

struct SigmaProtocolResponseMsgShort {
  std::vector<BIGNUM*> s;  // The second message which prover computed
  BIGNUM* c;               // challenge
  SigmaProtocolResponseMsgShort(size_t s_size) {
    c = BN_new();
    for (size_t i = 0; i < s_size; i++) {
      s.emplace_back(BN_new());
    }
  }

  SigmaProtocolResponseMsgShort(std::vector<BIGNUM*> s, BIGNUM* c) {
    for (size_t i = 0; i < s.size(); i++) {
      this->s.emplace_back(BN_new());
      BN_copy(this->s[i], s[i]);
    }
    c = BN_new();
    BN_copy(this->c, c);
  }

  SigmaProtocolResponseMsgShort(const SigmaProtocolResponseMsgShort& msg) {
    for (size_t i = 0; i < msg.s.size(); i++) {
      this->s.emplace_back(BN_new());
      BN_copy(this->s[i], msg.s[i]);
    }
    c = BN_new();
    BN_copy(this->c, msg.c);
  }

  ~SigmaProtocolResponseMsgShort() {
    for (size_t i = 0; i < s.size(); i++) {
      BN_free(s[i]);
    }
    BN_free(c);
  }
};

struct SigmaProtocolResponseMsgBatch {
  const EC_GROUP* group;
  std::vector<EC_POINT*> T;
  std::vector<BIGNUM*> s;

  SigmaProtocolResponseMsgBatch(const EC_GROUP* group, size_t T_size,
                                size_t s_size) {
    this->group = group;
    size_t i;
    this->T.reserve(T_size);
    this->s.reserve(s_size);
    for (i = 0; i < T_size; i++) {
      this->T.emplace_back(EC_POINT_new(group));
    }
    for (i = 0; i < s_size; i++) {
      this->s.emplace_back(BN_new());
    }
  }

  SigmaProtocolResponseMsgBatch(const EC_GROUP* group,
                                const std::vector<const EC_POINT*> T,
                                const std::vector<const BIGNUM*> s) {
    this->group = group;
    this->T.reserve(T.size());
    this->s.reserve(s.size());
    for (size_t i = 0; i < T.size(); i++) {
      this->T.emplace_back(EC_POINT_new(group));
      EC_POINT_copy(this->T[i], T[i]);
    }

    for (size_t i = 0; i < s.size(); i++) {
      this->s.emplace_back(BN_new());
      BN_copy(this->s[i], s[i]);
    }
  }

  SigmaProtocolResponseMsgBatch(const SigmaProtocolResponseMsgBatch& msg) {
    this->group = msg.group;
    this->T.reserve(msg.T.size());
    this->s.reserve(msg.s.size());
    for (size_t i = 0; i < msg.T.size(); i++) {
      this->T.emplace_back(EC_POINT_new(group));
      EC_POINT_copy(this->T[i], msg.T[i]);
    }

    for (size_t i = 0; i < msg.s.size(); i++) {
      this->s.emplace_back(BN_new());
      BN_copy(this->s[i], msg.s[i]);
    }
  }

  ~SigmaProtocolResponseMsgBatch() {
    for (size_t i = 0; i < T.size(); i++) {
      EC_POINT_free(T[i]);
    }

    for (size_t i = 0; i < s.size(); i++) {
      BN_free(s[i]);
    }
  }
};

// SigmaProtocolProver wants to prove that he/she knows {x_i}_{i \in [1,n]}
// which satisfy {Z_i}_{i \in [1,n]} = {[x_i]}_{i \in [1,n]}
class SigmaProtocolProverShort {
 public:
  SigmaProtocolProverShort(size_t x_size, size_t k_size, size_t s_size)
      : msg_(s_size), x_(x_size, nullptr), flag(false) {
    k_.reserve(k_size);
    for (size_t i = 0; i < k_size; i++) {
      k_.emplace_back(BN_new());
    }
  }

  SigmaProtocolProverShort(size_t x_size, size_t k_size, size_t s_size,
                           const std::vector<const BIGNUM*>& x)
      : msg_(s_size), x_(x_size, nullptr), flag(false) {
    k_.reserve(k_size);
    size_t i = 0;
    for (i = 0; i < k_size; i++) {
      k_.emplace_back(BN_new());
    }
    for (i = 0; i < x_size; i++) {
      this->x_[i] = x[i];
    }
  }

  virtual ~SigmaProtocolProverShort(){};

  virtual void Prove() = 0;

  std::vector<const BIGNUM*>& GetX() { return this->x_; }

  std::vector<BIGNUM*>& GetK() { return this->k_; }

  SigmaProtocolResponseMsgShort GetMsg() { return this->msg_; }

 protected:
  SigmaProtocolResponseMsgShort& GetMsgReference() { return this->msg_; }

 private:
  std::vector<const BIGNUM*> x_;  // witness vector
  std::vector<BIGNUM*> k_;        // random elements take from group G

  SigmaProtocolResponseMsgShort msg_;

  bool flag;
};

// This class
class SigmaProtocolProverBatch {
 public:
  SigmaProtocolProverBatch(const EC_GROUP* group, size_t x_size, size_t k_size,
                           size_t s_size, size_t T_size)
      : msg_(group, T_size, s_size), x_(x_size, nullptr), flag(false) {
    k_.reserve(k_size);
    for (size_t i = 0; i < k_size; i++) {
      k_.emplace_back(BN_new());
    }
  }

  SigmaProtocolProverBatch(const EC_GROUP* group, size_t x_size, size_t k_size,
                           size_t s_size, size_t T_size,
                           const std::vector<const BIGNUM*>& x)
      : msg_(group, T_size, s_size), x_(x_size, nullptr), flag(false) {
    k_.reserve(k_size);
    size_t i = 0;
    for (i = 0; i < k_size; i++) {
      k_.emplace_back(BN_new());
    }
    for (i = 0; i < x_size; i++) {
      this->x_[i] = x[i];
    }
  }

  virtual ~SigmaProtocolProverBatch(){};

  virtual void Prove() = 0;

  std::vector<const BIGNUM*>& GetX() { return this->x_; }

  std::vector<BIGNUM*>& GetK() { return this->k_; }

  SigmaProtocolResponseMsgBatch GetMsg() { return this->msg_; }

 protected:
  SigmaProtocolResponseMsgBatch& GetMsgReference() { return this->msg_; }

 private:
  std::vector<const BIGNUM*> x_;  // witness vector
  std::vector<BIGNUM*> k_;        // random elements take from group G

  SigmaProtocolResponseMsgBatch msg_;

  bool flag;
};

class SigmaProtocolVerifierShort {
 public:
  SigmaProtocolVerifierShort(const SigmaProtocolResponseMsgShort& msg)
      : msg_(msg) {}

  virtual bool Verify() = 0;

  SigmaProtocolResponseMsgShort& GetMsg() { return this->msg_; }

  virtual ~SigmaProtocolVerifierShort(){};

 private:
  SigmaProtocolResponseMsgShort msg_;
};

class SigmaProtocolVerifierBatch {
 public:
  SigmaProtocolVerifierBatch(const SigmaProtocolResponseMsgBatch& msg)
      : msg_(msg) {}

  virtual bool Verify() = 0;

  SigmaProtocolResponseMsgBatch& GetMsg() { return this->msg_; }

  virtual ~SigmaProtocolVerifierBatch(){};

 private:
  SigmaProtocolResponseMsgBatch msg_;
};

BIGNUM* SigmaProtocolGetChallenge(const SigmaProtocolCommonInput* params,
                                  const EC_POINT* T, BN_CTX* ctx);

BIGNUM* SigmaProtocolGetChallenge(const SigmaProtocolCommonInput* params,
                                  const std::vector<EC_POINT*>& T, BN_CTX* ctx);

}  // namespace yacl::crypto

#endif  // SIGMAPROTOCOL_SIGMAPROTOCOL_H
