#include "yacl/crypto/primitives/zkp/SigmaProtocol.h"

namespace yacl::crypto {

SigmaNIBatchProof SigmaProtocol::ProveBatch(
    const std::vector<MPInt>& witness, const std::vector<EcPoint>& statement,
    const std::vector<MPInt>& rnd_witness, ByteContainerView other_info) const {
  SigmaNIBatchProof ret_proof;
  ret_proof.rnd_statement.reserve(meta_.num_statement);
  ret_proof.proof.reserve(meta_.num_witness);
  ret_proof.type = meta_.type;
  // compute first message : rnd_statement
  ComputeFirstMsg(ret_proof.rnd_statement, rnd_witness);

  // get challenge: Hash(generators, statement ,rnd_statement)
  MPInt challenge =
      GetChallenge(statement, ret_proof.rnd_statement, other_info);

  // compute second message : proof
  ComputeSecondMsg(ret_proof.proof, witness, rnd_witness, challenge);

  return ret_proof;
}

bool SigmaProtocol::VerifyBatch(const std::vector<EcPoint>& statement,
                                const SigmaNIBatchProof& proof,
                                ByteContainerView other_info) const {
  MPInt challenge = GetChallenge(statement, proof.rnd_statement, other_info);

  EcPoint LHS = group_ref_->MulBase(0_mp);
  EcPoint RHS = group_ref_->MulBase(0_mp);
  uint32_t i;
  bool res = true;
  switch (meta_.type) {
    // verify: rnd_statement[i] + challenge * statement[i] ==
    // generator_ref_[i] * proof.proof[i]
    case SigmaType::Dlog:
      YACL_ENFORCE((meta_.num_generator == meta_.num_statement) &&
                   (meta_.num_generator == meta_.num_witness));
      for (i = 0; i < meta_.num_statement; i++) {
        LHS = group_ref_->Add(proof.rnd_statement[i],
                              group_ref_->Mul(statement[i], challenge));
        RHS = group_ref_->Mul(generator_ref_[i], proof.proof[i]);
        res &= group_ref_->PointEqual(LHS, RHS);
      }
      break;

    // verify: rnd_statement[0] + challenge * statement[0] == (generator_ref_[0]
    // * proof.proof[0]) + ... + (generator_ref_[n] * proof.proof[n])
    case SigmaType::Pedersen:
      YACL_ENFORCE((meta_.num_statement == 1) &&
                   (meta_.num_generator == meta_.num_witness));
      LHS = group_ref_->Add(group_ref_->Mul(statement[0], challenge),
                            proof.rnd_statement[0]);
      for (i = 0; i < meta_.num_witness; i++) {
        RHS = group_ref_->Add(
            RHS, group_ref_->Mul(generator_ref_[i], proof.proof[i]));
      }
      res &= group_ref_->PointEqual(LHS, RHS);
      break;
    // verify: rnd_statement[i] + challenge * statement[i] ==
    // generator_ref_[i] * proof.proof[0]
    case SigmaType::DlogEq:
    case SigmaType::DHTripple:
      YACL_ENFORCE((meta_.num_witness == 1) &&
                   (meta_.num_statement == meta_.num_generator));
      for (i = 0; i < meta_.num_statement; i++) {
        LHS = group_ref_->Add(proof.rnd_statement[i],
                              group_ref_->Mul(statement[i], challenge));
        RHS = group_ref_->Mul(generator_ref_[i], proof.proof[0]);
        res &= group_ref_->PointEqual(LHS, RHS);
      }
      break;

    default:
      YACL_THROW(
          "zkp lib only support Dlog, Pedersen, DlogEq, DHTripple "
          "SigmaProtocol now.");
  }
  return res;
}

SigmaNIShortProof SigmaProtocol::ProveShort(
    const std::vector<MPInt>& witness, const std::vector<EcPoint>& statement,
    const std::vector<MPInt>& rnd_witness, ByteContainerView other_info) const {
  SigmaNIShortProof ret_proof;
  std::vector<EcPoint> rnd_statement;
  rnd_statement.reserve(meta_.num_witness);
  ret_proof.proof.reserve(meta_.num_witness);
  ret_proof.type = meta_.type;

  ComputeFirstMsg(rnd_statement, rnd_witness);
  // get challenge: Hash(generators, statement ,rnd_statement)
  MPInt challenge = GetChallenge(statement, rnd_statement, other_info);

  // compute second message : proof
  ComputeSecondMsg(ret_proof.proof, witness, rnd_witness, challenge);

  return ret_proof;
}

bool SigmaProtocol::VerifyShort(const std::vector<EcPoint>& statement,
                                const SigmaNIShortProof& proof,
                                ByteContainerView other_info) {
  std::vector<EcPoint> rnd_statement;
  rnd_statement.reserve(meta_.num_statement);

  EcPoint tmp1 = group_ref_->MulBase(0_mp);
  EcPoint tmp2 = group_ref_->MulBase(0_mp);
  uint32_t i;

  // compute rnd_statement
  switch (meta_.type) {
    // rnd_statement[i] = (generator_ref_[i] * proof.proof[i]) - (challenge *
    // statement[i])
    case SigmaType::Dlog:
      YACL_ENFORCE((meta_.num_generator == meta_.num_statement) &&
                   (meta_.num_generator == meta_.num_witness));
      for (i = 0; i < meta_.num_statement; i++) {
        tmp1 = group_ref_->Mul(generator_ref_[i], proof.proof[i]);
        tmp2 = group_ref_->Mul(statement[i], proof.challenge);
        rnd_statement.emplace_back(group_ref_->Sub(tmp1, tmp2));
      }
      break;

    // rnd_statement[0] == (generator_ref_[0] * proof.proof[0])  + ...
    //  + (generator_ref_[n] * proof.proof[n]) - (challenge *statement[0])
    case SigmaType::Pedersen:
      YACL_ENFORCE((meta_.num_statement == 1) &&
                   (meta_.num_generator == meta_.num_witness));
      tmp2 = group_ref_->Mul(statement[0], proof.challenge);
      for (i = 0; i < meta_.num_witness; i++) {
        tmp1 = group_ref_->Add(
            tmp1, group_ref_->Mul(generator_ref_[i], proof.proof[i]));
      }
      rnd_statement.emplace_back(group_ref_->Sub(tmp1, tmp2));
      break;

    // verify: rnd_statement[i] == (generator_ref_[i] * proof.proof[0]) -
    // (challenge * statement[i])
    case SigmaType::DlogEq:
    case SigmaType::DHTripple:
      YACL_ENFORCE((meta_.num_witness == 1) &&
                   (meta_.num_statement == meta_.num_generator));
      for (i = 0; i < meta_.num_statement; i++) {
        tmp1 = group_ref_->Mul(generator_ref_[i], proof.proof[0]);
        tmp2 = group_ref_->Mul(statement[i], proof.challenge);
        rnd_statement.emplace_back(group_ref_->Sub(tmp1, tmp2));
      }
      break;

    default:
      YACL_THROW(
          "zkp lib only support Dlog, Pedersen, DlogEq, DHTripple "
          "SigmaProtocol now.");
  }

  // compute challenge
  MPInt challenge = GetChallenge(statement, rnd_statement, other_info);

  return (challenge == proof.challenge);
}

void SigmaProtocol::ComputeFirstMsg(
    std::vector<EcPoint>& rnd_statement,
    const std::vector<MPInt>& rnd_witness) const {
  // Protocols are classified into the following types based on the one way
  // homomorphism functions used.
  uint32_t i;
  switch (meta_.type) {
    // Proof Knowledge of Several Values: G_i -> H_i, f_i(x_i) = h_i^x_i
    case SigmaType::Dlog:
      YACL_ENFORCE((meta_.num_generator == meta_.num_statement) &&
                   (meta_.num_generator == meta_.num_witness));
      for (i = 0; i < meta_.num_generator; i++) {
        rnd_statement.emplace_back(
            group_ref_->Mul(generator_ref_[i], rnd_witness[i]));
      }
      break;

    // Proof of Knowledge of a Representation: Z_q^m -> H, f(x_1, x_2,...,x_m) =
    // h_1^{x_1} +... +h_m^{xm}
    case SigmaType::Pedersen:
      YACL_ENFORCE((meta_.num_statement == 1) &&
                   (meta_.num_generator == meta_.num_witness));
      rnd_statement.emplace_back(
          group_ref_->Mul(generator_ref_[0], rnd_witness[0]));
      for (i = 1; i < meta_.num_generator; i++) {
        rnd_statement[0] =
            group_ref_->Add(rnd_statement[0],
                            group_ref_->Mul(generator_ref_[i], rnd_witness[i]));
      }
      break;
    // Proof of Equality of Embedded Values: G -> H_1 \times... H_n \times
    // f(x) = (h_1^x, h_2^x, ..., h_n^x)
    case SigmaType::DlogEq:
    case SigmaType::DHTripple:
      YACL_ENFORCE((meta_.num_witness == 1) &&
                   (meta_.num_statement == meta_.num_generator));
      for (i = 0; i < meta_.num_generator; i++) {
        rnd_statement.emplace_back(
            group_ref_->Mul(generator_ref_[i], rnd_witness[0]));
      }
      break;

    default:
      YACL_THROW(
          "zkp lib only support Dlog, Pedersen, DlogEq, DHTripple "
          "SigmaProtocol now.");
  }
}
MPInt SigmaProtocol::GetChallenge(const std::vector<EcPoint>& statement,
                                  const std::vector<EcPoint>& rnd_statement,
                                  ByteContainerView other_info) const {
  SslHash hash_fun(hash_);
  uint32_t i;
  for (i = 0; i < meta_.num_generator; i++) {
    hash_fun.Update(group_ref_->SerializePoint(generator_ref_[i]));
  }

  for (i = 0; i < meta_.num_statement; i++) {
    hash_fun.Update(group_ref_->SerializePoint(statement[i]));
  }

  for (i = 0; i < meta_.num_statement; i++) {
    hash_fun.Update(group_ref_->SerializePoint(rnd_statement[i]));
  }

  hash_fun.Update(other_info);
  const char* byte = (const char*)((hash_fun.CumulativeHash()).data());

  return (MPInt)byte;
}

void SigmaProtocol::ComputeSecondMsg(std::vector<MPInt>& proof,
                                     const std::vector<MPInt>& witness,
                                     const std::vector<MPInt>& rnd_witness,
                                     const MPInt& challenge) const {
  for (uint32_t i = 0; i < meta_.num_witness; i++) {
    proof.emplace_back((challenge * witness[i] + rnd_witness[i]) % order_);
  }
}

}  // namespace yacl::crypto