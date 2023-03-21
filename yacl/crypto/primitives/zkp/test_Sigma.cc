#include <chrono>
#include <iostream>

#include "DiffieHellmanTriple.h"
#include "PedersenCommitmentOpen.h"
#include "Schnorr.h"
#include "SigmaDlogEquality.h"

namespace yacl::crypto {

BN_CTX* ctx;
EC_GROUP* curve;
BIGNUM *a, *b, *p, *order;
EC_POINT* generator;

std::chrono::high_resolution_clock::time_point Prover_begin, Prover_end;
std::chrono::high_resolution_clock::time_point Verifier_begin, Verifier_end;
std::chrono::duration<double> time_span;

double p_time, v_time;

// This function is for testing purposes only, and is not and cannot be used to
// generate the generators of Pedersen Commitment Protocol
void SampleGenerator(const EC_GROUP* curve, EC_POINT* g) {
  BIGNUM* p = BN_new();
  BIGNUM* x = BN_new();
  EC_POINT* tmp = EC_POINT_new(curve);

  BN_CTX* ctx = BN_CTX_new();

  assert(EC_GROUP_get_curve(curve, p, nullptr, nullptr, ctx) == 1);
  const BIGNUM* cofactor = EC_GROUP_get0_cofactor(curve);
  int res = 1;
  while (res == 1) {
    BN_rand_range(x, p);

    assert(EC_POINT_mul(curve, g, x, nullptr, nullptr, ctx));
    assert(EC_POINT_mul(curve, tmp, nullptr, g, cofactor, ctx));
    res = EC_POINT_is_at_infinity(curve, g);
  }

  BN_free(x);
  BN_free(p);
  EC_POINT_free(tmp);
  BN_CTX_free(ctx);
}

void InitTest(int nid) {
  printf("\n-------------------InitTest --------------------------\n");
  printf("\ncurrent Curve NID:%d\n", nid);

  curve = EC_GROUP_new_by_curve_name(nid);
  ctx = BN_CTX_new();
  order = BN_new();
  generator = EC_POINT_new(curve);
  EC_GROUP_get_order(curve, order, ctx);
  EC_POINT_copy(generator, EC_GROUP_get0_generator(curve));
  EC_GROUP_get_curve(curve, p, a, b, ctx);

  printf("\n-------------------InitEnd --------------------------\n");
}

void EndTest() {
  EC_GROUP_free(curve);
  BN_CTX_free(ctx);
  BN_free(p);
  BN_free(a);
  BN_free(b);
  BN_free(order);
  EC_POINT_free(generator);
}

void SchnorrTest() {
  printf("\n-------------------SchnorrTest Begin--------------------------\n");
  BIGNUM* w = BN_new();
  EC_POINT* G = EC_POINT_new(curve);
  EC_POINT* H = EC_POINT_new(curve);

  SampleGenerator(curve, G);
  BN_rand_range(w, order);

  EC_POINT_mul(curve, H, nullptr, G, w, ctx);
  SchnorrCommonInput params(curve, G, H, "sha256");

  /* Schnorr Short test */
  printf("\n****************Schnorr Short test Begin****************\n");
  Prover_begin = std::chrono::high_resolution_clock::now();

  SchnorrProverShort Prover_short(params, w);
  Prover_short.Prove();
  SigmaProtocolResponseMsgShort Msg_short = Prover_short.GetMsg();

  Prover_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Prover_end - Prover_begin);
  p_time = time_span.count();

  // Verifier
  Verifier_begin = std::chrono::high_resolution_clock::now();
  SchnorrVerifierShort Verifier_short(params, Msg_short);
  bool res = Verifier_short.Verify();
  Verifier_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Verifier_end - Verifier_begin);
  v_time = time_span.count();

  if (res)
    printf("\nTest of Schnorr Short pass.\n");
  else
    printf("\nTest of Schnorr Short fail.\n");

  printf("Prover's running time: %.6f\n", p_time);
  printf("Verifier's running time: %.6f\n", v_time);

  printf("\n****************Schnorr Short test End****************\n");

  /* Schnorr Batch test */
  printf("\n****************Schnorr Batch test Begin****************\n");

  // Prover
  Prover_begin = std::chrono::high_resolution_clock::now();

  SchnorrProverBatch Prover_batch(params, w);
  Prover_batch.Prove();
  SigmaProtocolResponseMsgBatch Msg_batch = Prover_batch.GetMsg();

  Prover_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Prover_end - Prover_begin);
  p_time = time_span.count();

  // Verifier
  Verifier_begin = std::chrono::high_resolution_clock::now();
  SchnorrVerifierBatch Verifier_batch(params, Msg_batch);
  res = Verifier_batch.Verify();
  Verifier_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Verifier_end - Verifier_begin);
  v_time = time_span.count();

  if (res)
    printf("\nTest of Schnorr Batch pass.\n");
  else
    printf("\nTest of Schnorr Batch fail.\n");

  printf("Prover's running time: %.6f\n", p_time);
  printf("Verifier's running time: %.6f\n", v_time);

  printf("\n****************Schnorr Batch test End****************\n");
  BN_free(w);
  EC_POINT_free(G);
  EC_POINT_free(H);

  printf("\n-------------------SchnorrTest End-------------------\n");
}

void DlogEqualityTest() {
  printf(
      "\n-------------------DlogEqualityTest "
      "Begin--------------------------\n");
  // generate random witness w
  BIGNUM* w = BN_new();
  EC_POINT* Y1 = EC_POINT_new(curve);
  EC_POINT* Y2 = EC_POINT_new(curve);
  BN_rand_range(w, order);

  EC_POINT* G = EC_POINT_new(curve);
  EC_POINT* H = EC_POINT_new(curve);
  SampleGenerator(curve, G);
  SampleGenerator(curve, H);

  EC_POINT_mul(curve, Y1, nullptr, G, w, ctx);
  EC_POINT_mul(curve, Y2, nullptr, H, w, ctx);

  DlogEqualityCommonInput params(curve, G, H, Y1, Y2, "sha256");

  printf("\n****************DlogEquality Short test Begin****************\n");

  // Prover
  Prover_begin = std::chrono::high_resolution_clock::now();
  DlogEqualityProverShort Prover_short(params, w);

  Prover_short.Prove();
  SigmaProtocolResponseMsgShort Msg_short = Prover_short.GetMsg();
  Prover_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Prover_end - Prover_begin);
  p_time = time_span.count();

  // Verifier
  Verifier_begin = std::chrono::high_resolution_clock::now();
  DlogEqualityVerifierShort Verifier_short(params, Msg_short);

  bool res = Verifier_short.Verify();

  Verifier_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Verifier_end - Verifier_begin);
  v_time = time_span.count();

  if (res)
    printf("\nTest of DlogEquality pass.\n");
  else
    printf("\nTest of DlogEquality fail.\n");

  printf("Prover's running time: %.6f\n", p_time);
  printf("Verifier's running time: %.6f\n", v_time);

  printf("\n****************DlogEquality Short test End****************\n");

  printf("\n****************DlogEquality Batch test Begin****************\n");
  // Prover
  Prover_begin = std::chrono::high_resolution_clock::now();
  DlogEqualityProverBatch Prover_batch(params, w);

  Prover_batch.Prove();
  SigmaProtocolResponseMsgBatch Msg_batch = Prover_batch.GetMsg();
  Prover_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Prover_end - Prover_begin);
  p_time = time_span.count();

  // Verifier
  Verifier_begin = std::chrono::high_resolution_clock::now();
  DlogEqualityVerifierBatch Verifier_batch(params, Msg_batch);

  res = Verifier_batch.Verify();

  Verifier_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Verifier_end - Verifier_begin);
  v_time = time_span.count();

  if (res)
    printf("\nTest of DlogEquality pass.\n");
  else
    printf("\nTest of DlogEquality fail.\n");

  printf("Prover's running time: %.6f\n", p_time);
  printf("Verifier's running time: %.6f\n", v_time);

  printf("\n****************DlogEquality Batch test End****************\n");

  EC_POINT_free(Y1);
  EC_POINT_free(Y2);
  EC_POINT_free(G);
  EC_POINT_free(H);
  BN_free(w);

  printf(
      "\n-------------------DlogEqualityTest End--------------------------\n");
}

void PedersenCommitmentOpenTest() {
  printf(
      "\n-------------------PedersenCommitmentOpenTest "
      "Begin--------------------------\n");
  // get generators
  EC_POINT* G = EC_POINT_new(curve);
  EC_POINT* H = EC_POINT_new(curve);
  SampleGenerator(curve, H);
  SampleGenerator(curve, G);

  // test commitment
  EC_POINT* com = EC_POINT_new(curve);
  EC_POINT* tmp = EC_POINT_new(curve);

  // get witnesses
  BIGNUM* w1 = BN_new();
  BIGNUM* w2 = BN_new();
  BN_rand_range(w1, order);
  BN_rand_range(w2, order);

  // com = w1*G + w2*H
  EC_POINT_mul(curve, com, nullptr, G, w1, ctx);
  EC_POINT_mul(curve, tmp, nullptr, H, w2, ctx);
  EC_POINT_add(curve, com, com, tmp, ctx);

  PedersenCommitmentCommonInput params(curve, G, H, com, "sha256");

  printf(
      "\n****************PedersenCommitment Short test "
      "Begin****************\n");
  // Prover
  Prover_begin = std::chrono::high_resolution_clock::now();
  PedersenCommitmentProverShort prover_short(params, w1, w2);
  prover_short.Prove();

  SigmaProtocolResponseMsgShort Msg_short = prover_short.GetMsg();
  Prover_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Prover_end - Prover_begin);
  p_time = time_span.count();

  // Verifier
  Verifier_begin = std::chrono::high_resolution_clock::now();
  PedersemCommitmentVerifierShort verifier_short(params, Msg_short);

  int res = verifier_short.Verify();
  Verifier_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Verifier_end - Verifier_begin);
  v_time = time_span.count();

  if (res)
    printf("\nTest of PedersenCommitmentOpenTest pass.\n");
  else
    printf("\nTest of PedersenCommitmentOpenTest fail.\n");

  printf("Prover's running time: %.6f\n", p_time);
  printf("Verifier's running time: %.6f\n", v_time);

  printf(
      "\n****************PedersenCommitment Short test "
      "End****************\n");

  // Prover
  Prover_begin = std::chrono::high_resolution_clock::now();
  PedersenCommitmentProverBatch prover_batch(params, w1, w2);
  prover_batch.Prove();

  SigmaProtocolResponseMsgBatch Msg_batch = prover_batch.GetMsg();
  Prover_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Prover_end - Prover_begin);
  p_time = time_span.count();

  // Verifier
  Verifier_begin = std::chrono::high_resolution_clock::now();
  PedersemCommitmentVerifierBatch verifier_batch(params, Msg_batch);

  res = verifier_batch.Verify();
  Verifier_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Verifier_end - Verifier_begin);
  v_time = time_span.count();

  if (res)
    printf("\nTest of PedersenCommitmentOpenTest pass.\n");
  else
    printf("\nTest of PedersenCommitmentOpenTest fail.\n");

  printf("Prover's running time: %.6f\n", p_time);
  printf("Verifier's running time: %.6f\n", v_time);

  printf(
      "\n****************PedersenCommitment Batch test "
      "Begin****************\n");

  printf(
      "\n****************PedersenCommitment Batch test "
      "End****************\n");

  EC_POINT_free(G);
  EC_POINT_free(H);
  EC_POINT_free(com);
  EC_POINT_free(tmp);
  BN_free(w1);
  BN_free(w2);

  printf(
      "\n-------------------PedersenCommitmentOpenTest "
      "End--------------------------\n");
}

void DiffieHellmanTest() {
  printf(
      "\n-------------------DiffieHellmanTest "
      "Begin--------------------------\n");
  EC_POINT* Y1 = EC_POINT_new(curve);
  EC_POINT* Y2 = EC_POINT_new(curve);
  EC_POINT* Y3 = EC_POINT_new(curve);

  BIGNUM* w1 = BN_new();
  BIGNUM* w2 = BN_new();
  BN_rand_range(w1, order);
  BN_rand_range(w2, order);

  EC_POINT_mul(curve, Y1, w1, nullptr, nullptr, ctx);
  EC_POINT_mul(curve, Y2, w2, nullptr, nullptr, ctx);
  EC_POINT_mul(curve, Y3, nullptr, Y1, w2, ctx);

  DiffieHellmanTripleCommonInput params(curve, generator, Y1, Y2, Y3);
  printf(
      "\n****************DiffieHellman Short test "
      "Begin****************\n");

  // Prover
  Prover_begin = std::chrono::high_resolution_clock::now();
  DiffieHellmanTripleProverShort prover_short(params, w1, w2);

  prover_short.Prove();
  SigmaProtocolResponseMsgShort Msg_short = prover_short.GetMsg();
  Prover_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Prover_end - Prover_begin);
  p_time = time_span.count();

  // Verifier
  Verifier_begin = std::chrono::high_resolution_clock::now();
  DiffieHellmanTripleVerifierShort verifier_short(params, Msg_short);
  bool res = verifier_short.Verify();
  Verifier_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Verifier_end - Verifier_begin);
  v_time = time_span.count();

  if (res)
    printf("\nTest of DiffieHellman pass.\n");
  else
    printf("\nTest of DiffieHellman fail.\n");

  printf("Prover's running time: %.6f\n", p_time);
  printf("Verifier's running time: %.6f\n", v_time);

  printf(
      "\n****************DiffieHellman Short test "
      "End****************\n");

  printf(
      "\n****************DiffieHellman Batch test "
      "Begin****************\n");

  // Prover
  Prover_begin = std::chrono::high_resolution_clock::now();
  DiffieHellmanTripleProverBatch prover_batch(params, w1, w2);

  prover_batch.Prove();
  SigmaProtocolResponseMsgBatch Msg_batch = prover_batch.GetMsg();
  Prover_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Prover_end - Prover_begin);
  p_time = time_span.count();

  // Verifier
  Verifier_begin = std::chrono::high_resolution_clock::now();
  DiffieHellmanTripleVerifierBatch verifier_batch(params, Msg_batch);
  res = verifier_batch.Verify();
  Verifier_end = std::chrono::high_resolution_clock::now();
  time_span = std::chrono::duration_cast<std::chrono::duration<double>>(
      Verifier_end - Verifier_begin);
  v_time = time_span.count();

  if (res)
    printf("\nTest of DiffieHellman pass.\n");
  else
    printf("\nTest of DiffieHellman fail.\n");

  printf("Prover's running time: %.6f\n", p_time);
  printf("Verifier's running time: %.6f\n", v_time);

  printf(
      "\n****************DiffieHellman Batch test "
      "End****************\n");

  EC_POINT_free(Y1);
  EC_POINT_free(Y2);
  EC_POINT_free(Y3);
  BN_free(w1);
  BN_free(w2);

  printf(
      "\n-------------------DiffieHellmanTest End--------------------------\n");
}

}  // namespace yacl::crypto
int main() {
  yacl::crypto::InitTest(NID_secp256k1);

  yacl::crypto::SchnorrTest();

  yacl::crypto::DlogEqualityTest();

  yacl::crypto::DiffieHellmanTest();

  yacl::crypto::PedersenCommitmentOpenTest();

  yacl::crypto::EndTest();
  return 0;
}
