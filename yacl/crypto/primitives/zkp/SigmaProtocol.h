#ifndef SIGMAPROTOCOL_H
#define SIGMAPROTOCOL_H

#pragma once

#include "yacl/crypto/base/ecc/ec_point.h"
#include "yacl/crypto/base/ecc/openssl/openssl_group.h"
#include "yacl/crypto/base/hash/ssl_hash.h"
#include "yacl/crypto/tools/random_oracle.h"

namespace yacl::crypto {

enum class SigmaType {
  // Description: know the result of discrete logarithm.
  // f : x -> h1^x (1 1 1, 1 elements in G, 1 Generator and 1 elements in H).
  // Secret: x (in group G).
  // Statement:  z = h1^x (in group H).
  Dlog,
  // Description: know the opening of Pedersen commitment.
  // f : (x1, x2) -> h1^x1·h2^x2 (2 2 1),
  // Secret: x1, x2,
  // Statement:  z = h1^x1·h2^x2.
  Pedersen,
  // Description: know the representation over generators h1, ..., hn.
  // f : (x1, x2, ..., xn) -> h1^x1·h2^x2·...·hn^xn (n n 1),
  // Secret: x1, x2, ..., xn,
  // Statement:  z = h1^x1·h2^x2·...·hn^xn.
  Representation,
  // Description: know results of several discrete logarithm.
  // f : (x1, x2, ..., xn) -> (h1^x1, h2^x2, ..., hn^xn) (n n n),
  // Secret: x1, x2, ..., xn,
  // Statement:  z = (h1^x1, h2^x2, ..., hn^xn).
  SeveralDlog,
  // Description: know equality of two discrete logarithm.
  // f : x -> h1^x, h2^x (1 2 2),
  // Secret: x,
  // Statement:  z1 = h1^x, z2 = h2^x.
  DlogEq,
  // Description: know equality of several discrete logarithm.
  // f : x -> h1^x, h2^x2, ..., hn^xn (1 n n),
  // Secret: x,
  // Statement:  z1 = h1^x, z2 = h2^x, ..., zn = hn^x.
  SeveralDlogEq,
  // Description: know correctness of Diffie-Hellman Keys. (1 2 2)
  // Note: It's underlying homomorphism is DlogEq.
  // Secret: x1,
  // Statement:  z1 = h1^x1, z2 = h1^x2, z3 = h1^{x1·x2} = z2^x1,
  // Generators define & transform: h1=h1, h2 = z2,
  // Transformed statement: z1 = h1^x1, z3= h2^x1 (Actually DlogEq).
  DHTripple,
  // Description: know underlying multiplication relation of three Pedersen
  // commitments. (5 2 3)
  // Note: It's underlying homomorphism is Pedersen.
  // (Note: We don't count x3 as a secret, cause it's a derived secret by x1·x2)
  // Secret: x1, r1, x2, r2, x3 (x1·x2 is the derived witness), r3
  // Statement:
  //             z1 = h1^x1·h2^r1,
  //             z2 = h1^x2·h2^r2,
  //             z3 = h1^x3·h2^r3,
  //             x3 = x1 * x2,
  // Generators define & transform: h1 = h1, h2 = h2, h3 = z1
  // Transformed statement:
  //             z1 = h1^x1·h2^r1,
  //             z2 = h1^x2·h2^r2,
  //             z3 = h3^x2·h2^(r3-x2·r1) (implying z3 has x3 = x1 * x2),
  // So we could proof that we have witnesses to open such 3 commitments(z1, z2,
  // z3)
  PedersenMult,
  // Description: know underlying multiplication relation of three Pedersen
  //   commitments, but here we could choose to open a pair (x, r).
  // Note: It's underlying homomorphism is Pedersen.
  // Secret: x1, r1, (x2, r2), x3, r3 [Choose open x2, r2]
  PedersenMultOpenOne,
};

struct SigmaMeta {
  SigmaType type;
  uint32_t num_witness;
  uint32_t num_generator;
  uint32_t num_statement;         // number of group H's elements in statement
  bool varied_size_flag = false;  // true for any numXXX is 0
};

struct SigmaNIShortProof {
  SigmaType type;
  std::vector<MPInt> proof;
  MPInt challenge;
};

struct SigmaNIBatchProof {
  SigmaType type;
  std::vector<MPInt> proof;
  std::vector<EcPoint> rnd_statement;
};

class SigmaProtocol {
 public:
  explicit SigmaProtocol(const std::unique_ptr<EcGroup>& group,
                         const std::vector<EcPoint>& generator, SigmaMeta meta,
                         HashAlgorithm hash = HashAlgorithm::SHA256)
      : group_ref_(group),
        generator_ref_(generator),
        meta_(meta),
        order_(group_ref_->GetOrder()),
        hash_(hash) {}

  // other_info for generation of challenge as H(...||other_info)
  // rnd_witness is the same number of random stuffs for proof
  SigmaNIBatchProof ProveBatch(const std::vector<MPInt>& witness,
                               const std::vector<EcPoint>& statement,
                               const std::vector<MPInt>& rnd_witness,
                               ByteContainerView other_info) const;
  bool VerifyBatch(const std::vector<EcPoint>& statement,
                   const SigmaNIBatchProof& proof,
                   ByteContainerView other_info) const;

  SigmaNIShortProof ProveShort(const std::vector<MPInt>& witness,
                               const std::vector<EcPoint>& statement,
                               const std::vector<MPInt>& rnd_witness,
                               ByteContainerView other_info) const;
  bool VerifyShort(const std::vector<EcPoint>& statement,
                   const SigmaNIShortProof& proof,
                   ByteContainerView other_info);

  std::vector<EcPoint> ToStatement(const std::vector<MPInt>& witness) const;

 private:
  MPInt GetChallenge(const std::vector<EcPoint>& statement,
                     const std::vector<EcPoint>& rnd_statement,
                     ByteContainerView other_info) const;

  std::vector<MPInt> ToProof(const std::vector<MPInt>& witness,
                             const std::vector<MPInt>& rnd_witness,
                             const MPInt& challenge) const;

  const std::unique_ptr<EcGroup>& group_ref_;
  const std::vector<EcPoint>& generator_ref_;
  const SigmaMeta meta_;
  const MPInt order_;  // [0, order_-1] as challenge space
  const HashAlgorithm hash_;
};

}  // namespace yacl::crypto

#endif  // SIGMAPROTOCOL_H