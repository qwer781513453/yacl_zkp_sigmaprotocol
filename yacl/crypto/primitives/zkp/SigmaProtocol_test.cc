#include "yacl/crypto/primitives/zkp/SigmaProtocol.h"

#include "gtest/gtest.h"

namespace yacl::crypto::test {

class SigmaProtocolTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = openssl::OpensslGroup::Create(GetCurveMetaByName("sm2"));
    n_ = curve_->GetOrder();
    auto cofactor = curve_->GetCofactor();

    witness_.resize(3, (MPInt)0);
    rnd_witness_.resize(3, (MPInt)0);
    generators_.reserve(3);
    for (uint32_t i = 0; i < 3; i++) {
      // init random witness & rnd_witness
      MPInt::RandomLtN(n_, &witness_[0]);
      MPInt::RandomLtN(n_, &rnd_witness_[0]);

      // sample generators
      generators_.emplace_back(curve_->MulBase(0_mp));
      uint32_t j = 0;
      EcPoint tmp = curve_->MulBase(0_mp);
      while (curve_->IsInfinity(tmp)) {
        tmp = curve_->HashToCurve(HashToCurveStrategy::TryAndRehash_SHA2,
                                  fmt::format("id{}", j++));
        generators_[i] = tmp;
        curve_->MulInplace(&tmp, cofactor);
      }
    }
  }

  void StartTest(SigmaMeta SigmaType, ByteContainerView other_info) {
    SigmaProtocol protocol(curve_, generators_, SigmaType);
    std::vector<EcPoint> statement = protocol.ToStatement(witness_);

    auto proof_batch =
        protocol.ProveBatch(witness_, statement, rnd_witness_, other_info);

    EXPECT_TRUE(protocol.VerifyBatch(statement, proof_batch, other_info));

    auto proof_short =
        protocol.ProveShort(witness_, statement, rnd_witness_, other_info);

    EXPECT_TRUE(protocol.VerifyShort(statement, proof_short, other_info));
  }

  std::unique_ptr<yacl::crypto::EcGroup> curve_;
  MPInt n_;

  std::vector<MPInt> witness_;
  std::vector<MPInt> rnd_witness_;
  std::vector<EcPoint> generators_;
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