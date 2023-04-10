#include "yacl/crypto/primitives/zkp/SigmaProtocol.h"

#include "gtest/gtest.h"

namespace yacl::crypto::test {

auto curve = openssl::OpensslGroup::Create(GetCurveMetaByName("sm2"));
MPInt n = curve->GetOrder();

TEST(SigmaProtocolTest, DlogTest) {
  SigmaMeta Dlog = {SigmaType::Dlog, 1, 1, 1};

  std::vector<MPInt> witness;
  std::vector<MPInt> rnd_witness;
  ByteContainerView other_info("DlogTest");

  witness.emplace_back(0);
  MPInt::RandomLtN(n, &witness[0]);
  rnd_witness.emplace_back(0);
  MPInt::RandomLtN(n, &rnd_witness[0]);

  std::vector<EcPoint> generators;
  generators.emplace_back(curve->GetGenerator());

  SigmaProtocol protocol(curve, generators, Dlog);
  std::vector<EcPoint> statement = protocol.ToStatement(witness);

  auto proof = protocol.ProveBatch(witness, statement, rnd_witness, other_info);

  EXPECT_TRUE(protocol.VerifyBatch(statement, proof, other_info));
}

}  // namespace yacl::crypto::test