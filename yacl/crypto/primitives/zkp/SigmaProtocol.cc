#include "yacl/crypto/primitives/zkp/SigmaProtocol.h"

#include "yacl/base/dynamic_bitset.h"

namespace yacl::crypto {

SigmaNIBatchProof SigmaProtocol::ProveBatch(
    const std::vector<MPInt>& witness, const std::vector<EcPoint>& statement,
    const std::vector<MPInt>& rnd_witness, ByteContainerView other_info) const {
  SigmaNIBatchProof ret_proof;
  ret_proof.type = meta_.type;

  // compute first message : rnd_statement
  ret_proof.rnd_statement = ToStatement(rnd_witness);

  // get challenge: Hash(generators, statement ,rnd_statement)
  MPInt challenge =
      GetChallenge(statement, ret_proof.rnd_statement, other_info);

  // compute second message : proof
  ret_proof.proof = ToProof(witness, rnd_witness, challenge);

  return ret_proof;
}

bool SigmaProtocol::VerifyBatch(const std::vector<EcPoint>& statement,
                                const SigmaNIBatchProof& proof,
                                ByteContainerView other_info) const {
  MPInt challenge = GetChallenge(statement, proof.rnd_statement, other_info);

  uint32_t i;
  bool res = true;

  switch (meta_.type) {
    // verify: rnd_statement[0] + challenge * statement[0] == (generator_ref_[0]
    // * proof.proof[0]) + ... + (generator_ref_[n] * proof.proof[n])
    case SigmaType::Dlog:
    case SigmaType::Pedersen:
    case SigmaType::Representation: {
      YACL_ENFORCE((meta_.num_statement == 1) &&
                   (meta_.num_generator == meta_.num_witness));
      EcPoint RHS = group_ref_->MulBase(0_mp);
      for (i = 0; i < meta_.num_witness; i++) {
        RHS = group_ref_->Add(
            RHS, group_ref_->Mul(generator_ref_[i], proof.proof[i]));
      }
      res &= group_ref_->PointEqual(
          group_ref_->Add(group_ref_->Mul(statement[0], challenge),
                          proof.rnd_statement[0]),
          RHS);
      break;
    }
    // verify: rnd_statement[i] + challenge * statement[i] ==
    // generator_ref_[i] * proof.proof[i]
    case SigmaType::SeveralDlog:
      YACL_ENFORCE((meta_.num_generator == meta_.num_statement) &&
                   (meta_.num_generator == meta_.num_witness));
      for (i = 0; i < meta_.num_statement; i++) {
        res &= group_ref_->PointEqual(
            group_ref_->Add(proof.rnd_statement[i],
                            group_ref_->Mul(statement[i], challenge)),
            group_ref_->Mul(generator_ref_[i], proof.proof[i]));
      }
      break;

    // verify: rnd_statement[i] + challenge * statement[i] ==
    // generator_ref_[i] * proof.proof[0]
    case SigmaType::DlogEq:
    case SigmaType::SeveralDlogEq:
    case SigmaType::DHTripple:
      YACL_ENFORCE((meta_.num_witness == 1) &&
                   (meta_.num_statement == meta_.num_generator));
      for (i = 0; i < meta_.num_statement; i++) {
        res &= group_ref_->PointEqual(
            group_ref_->Add(proof.rnd_statement[i],
                            group_ref_->Mul(statement[i], challenge)),
            group_ref_->Mul(generator_ref_[i], proof.proof[0]));
      }
      break;

    default:
      YACL_THROW(
          "zkp lib only support Dlog, Pedersen, Representation, SeveralDlog, "
          "DlogEq, SeveralDlogEq, DHTripple, "
          "SigmaProtocol now.");
  }
  return res;
}

SigmaNIShortProof SigmaProtocol::ProveShort(
    const std::vector<MPInt>& witness, const std::vector<EcPoint>& statement,
    const std::vector<MPInt>& rnd_witness, ByteContainerView other_info) const {
  SigmaNIShortProof ret_proof;
  std::vector<EcPoint> rnd_statement;
  rnd_statement = ToStatement(rnd_witness);
  ret_proof.type = meta_.type;

  // get challenge: Hash(generators, statement ,rnd_statement)
  ret_proof.challenge = GetChallenge(statement, rnd_statement, other_info);

  // compute second message : proof
  ret_proof.proof = ToProof(witness, rnd_witness, ret_proof.challenge);

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
    // rnd_statement[0] == (generator_ref_[0] * proof.proof[0])  + ...
    //  + (generator_ref_[n] * proof.proof[n]) - (challenge *statement[0])
    case SigmaType::Dlog:
    case SigmaType::Pedersen:
    case SigmaType::Representation:
      YACL_ENFORCE((meta_.num_statement == 1) &&
                   (meta_.num_generator == meta_.num_witness));
      tmp2 = group_ref_->Mul(statement[0], proof.challenge);
      for (i = 0; i < meta_.num_witness; i++) {
        tmp1 = group_ref_->Add(
            tmp1, group_ref_->Mul(generator_ref_[i], proof.proof[i]));
      }
      rnd_statement.emplace_back(group_ref_->Sub(tmp1, tmp2));
      break;

    // rnd_statement[i] = (generator_ref_[i] * proof.proof[i]) - (challenge *
    // statement[i])
    case SigmaType::SeveralDlog:
      YACL_ENFORCE((meta_.num_generator == meta_.num_statement) &&
                   (meta_.num_generator == meta_.num_witness));
      for (i = 0; i < meta_.num_statement; i++) {
        tmp1 = group_ref_->Mul(generator_ref_[i], proof.proof[i]);
        tmp2 = group_ref_->Mul(statement[i], proof.challenge);
        rnd_statement.emplace_back(group_ref_->Sub(tmp1, tmp2));
      }
      break;

    // verify: rnd_statement[i] == (generator_ref_[i] * proof.proof[0]) -
    // (challenge * statement[i])
    case SigmaType::DlogEq:
    case SigmaType::SeveralDlogEq:
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
          "zkp lib only support Dlog, Pedersen, Representation, SeveralDlog, "
          "DlogEq, SeveralDlogEq, DHTripple, "
          "SigmaProtocol now.");
  }

  // compute challenge
  MPInt challenge = GetChallenge(statement, rnd_statement, other_info);

  return (challenge == proof.challenge);
}

std::vector<EcPoint> SigmaProtocol::ToStatement(
    const std::vector<MPInt>& witness) const {
  std::vector<EcPoint> statement;
  statement.reserve(meta_.num_statement);
  // Protocols are classified into the following types based on the one way
  // homomorphism functions used.
  uint32_t i;
  switch (meta_.type) {
    // Proof of Knowledge of a Representation: Z_q^m -> H, f(x_1, x_2,...,x_m) =
    // h_1^{x_1} +... +h_m^{xm}
    case SigmaType::Dlog:
    case SigmaType::Pedersen:
    case SigmaType::Representation:
      YACL_ENFORCE((meta_.num_statement == 1) &&
                   (meta_.num_generator == meta_.num_witness));
      statement.emplace_back(group_ref_->Mul(generator_ref_[0], witness[0]));
      for (i = 1; i < meta_.num_generator; i++) {
        statement[0] = group_ref_->Add(
            statement[0], group_ref_->Mul(generator_ref_[i], witness[i]));
      }
      break;

    // Proof Knowledge of Several Values: G_i -> H_i, f_i(x_i) = h_i^x_i
    case SigmaType::SeveralDlog:
      YACL_ENFORCE((meta_.num_generator == meta_.num_statement) &&
                   (meta_.num_generator == meta_.num_witness));
      for (i = 0; i < meta_.num_generator; i++) {
        statement.emplace_back(group_ref_->Mul(generator_ref_[i], witness[i]));
      }
      break;

    // Proof of Equality of Embedded Values: G -> H_1 \times... H_n \times
    // f(x) = (h_1^x, h_2^x, ..., h_n^x)
    case SigmaType::DlogEq:
    case SigmaType::DHTripple:
    case SigmaType::SeveralDlogEq:
      YACL_ENFORCE((meta_.num_witness == 1) &&
                   (meta_.num_statement == meta_.num_generator));
      for (i = 0; i < meta_.num_generator; i++) {
        statement.emplace_back(group_ref_->Mul(generator_ref_[i], witness[0]));
      }
      break;

    default:
      YACL_THROW(
          "zkp lib only support Dlog, Pedersen, Representation, SeveralDlog, "
          "DlogEq, SeveralDlogEq, DHTripple, "
          "SigmaProtocol now.");
  }
  return statement;
}
MPInt SigmaProtocol::GetChallenge(const std::vector<EcPoint>& statement,
                                  const std::vector<EcPoint>& rnd_statement,
                                  ByteContainerView other_info) const {
  RandomOracle ro(hash_, 32);
  std::vector<Buffer> buf_vec;
  buf_vec.reserve(meta_.num_statement * 2 + meta_.num_generator);
  uint32_t i;

  for (i = 0; i < meta_.num_generator; i++) {
    buf_vec.emplace_back(group_ref_->SerializePoint(generator_ref_[i]));
  }

  for (i = 0; i < meta_.num_statement; i++) {
    buf_vec.emplace_back(group_ref_->SerializePoint(statement[i]));
  }

  for (i = 0; i < meta_.num_statement; i++) {
    buf_vec.emplace_back(group_ref_->SerializePoint(rnd_statement[i]));
  }

  auto out = ro.Gen<std::array<uint8_t, 32>>({*(buf_vec.data()), other_info});

  // TODO: replace this step with BytesToMPInt();
  dynamic_bitset<uint8_t> binary;
  binary.append(out.begin(), out.end());
  MPInt hash_bn(binary.to_string(), 2);
  return hash_bn;
}

std::vector<MPInt> SigmaProtocol::ToProof(const std::vector<MPInt>& witness,
                                          const std::vector<MPInt>& rnd_witness,
                                          const MPInt& challenge) const {
  std::vector<MPInt> proof;
  proof.reserve(meta_.num_witness);
  for (uint32_t i = 0; i < meta_.num_witness; i++) {
    proof.emplace_back((challenge * witness[i] + rnd_witness[i]) % order_);
  }
  return proof;
}

}  // namespace yacl::crypto