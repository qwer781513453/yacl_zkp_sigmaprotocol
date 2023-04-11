#include "yacl/crypto/primitives/zkp/SigmaProtocol.h"

#include "gtest/gtest.h"

namespace yacl::crypto::test {

class SigmaProtocolTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve = openssl::OpensslGroup::Create(GetCurveMetaByName("sm2"));
    n = curve->GetOrder();
    auto cofactor = curve->GetCofactor();

    witness.resize(3, (MPInt)0);
    rnd_witness.resize(3, (MPInt)0);
    generators.reserve(3);
    for (uint32_t i = 0; i < 3; i++) {
      // init random witness & rnd_witness
      MPInt::RandomLtN(n, &witness[0]);
      MPInt::RandomLtN(n, &rnd_witness[0]);

      // sample generators
      generators.emplace_back(curve->MulBase(0_mp));
      uint32_t j = 0;
      EcPoint tmp = curve->MulBase(0_mp);
      while (curve->IsInfinity(tmp)) {
        tmp = curve->HashToCurve(HashToCurveStrategy::TryAndRehash_SHA2,
                                 fmt::format("id{}", j++));
        generators[i] = tmp;
        curve->MulInplace(&tmp, cofactor);
      }
    }
  }

  void StartTest(SigmaMeta SigmaType, ByteContainerView other_info) {
    SigmaProtocol protocol(curve, generators, SigmaType);
    std::vector<EcPoint> statement = protocol.ToStatement(witness);

    auto proof_batch =
        protocol.ProveBatch(witness, statement, rnd_witness, other_info);

    EXPECT_TRUE(protocol.VerifyBatch(statement, proof_batch, other_info));

    auto proof_short =
        protocol.ProveShort(witness, statement, rnd_witness, other_info);

    EXPECT_TRUE(protocol.VerifyShort(statement, proof_short, other_info));
  }

  std::unique_ptr<yacl::crypto::EcGroup> curve;
  MPInt n;

  std::vector<MPInt> witness;
  std::vector<MPInt> rnd_witness;
  std::vector<EcPoint> generators;
};

TEST_F(SigmaProtocolTest, DlogTest) {
  SigmaMeta Dlog = {SigmaType::Dlog, 1, 1, 1};
  ByteContainerView other_info("DlogTest");
  StartTest(Dlog, other_info);
}

TEST_F(SigmaProtocolTest, RepresentationTest) {
  // The Pedersen is the same as RepresentationTest
  SigmaMeta Representation = {SigmaType::Representation, 3, 3, 1};
  ByteContainerView other_info("RepresentationTest");
  StartTest(Representation, other_info);
}

TEST_F(SigmaProtocolTest, SeveralDlogTest) {
  SigmaMeta SeveralDlog = {SigmaType::SeveralDlog, 3, 3, 3};
  ByteContainerView other_info("SeveralDlogTest");
  StartTest(SeveralDlog, other_info);
}

TEST_F(SigmaProtocolTest, SeveralDlogEqTest) {
  SigmaMeta SeveralDlogEq = {SigmaType::SeveralDlogEq, 1, 3, 3};
  ByteContainerView other_info("SeveralDlogEqTest");
  StartTest(SeveralDlogEq, other_info);
}

TEST_F(SigmaProtocolTest, DHTrippleTest) {
  SigmaMeta DHTripple = {SigmaType::DHTripple, 1, 2, 2};
  ByteContainerView other_info("DHTrippleTest");
  StartTest(DHTripple, other_info);
}

}  // namespace yacl::crypto::test