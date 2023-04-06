#ifndef SIGMAPROTOCOL_H
#define SIGMAPROTOCOL_H

#pragma once

#include "yacl/crypto/base/ecc/ec_point.h"
#include "yacl/crypto/base/ecc/openssl/openssl_group.h"
#include "yacl/crypto/base/hash/ssl_hash.h"

namespace yacl::crypto {

enum class SigmaType {
  Dlog,       // witness 1 generator 1 statement 1
  Pedersen,   // witness 2 generator 2 statement 1
  DlogEq,     // witness 1 generator 2 statement 2
  DHTripple,  // witness 1 generator 2 statement 2 (g^a, g^ab). g^b as a
              // generator, and b is not visible for a's holder.
  //...
};

#define SigmaTypeNum 4

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

 private:
  void ComputeFirstMsg(std::vector<EcPoint>& rnd_statement,
                       const std::vector<MPInt>& rnd_witness) const;

  MPInt GetChallenge(const std::vector<EcPoint>& statement,
                     const std::vector<EcPoint>& rnd_statement,
                     ByteContainerView other_info) const;

  void ComputeSecondMsg(std::vector<MPInt>& proof,
                        const std::vector<MPInt>& witness,
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