#include "seal/seal.h"

#include <assert.h>
#include <stdlib.h>

#include <memory>
#include <string>

#include "utils/utils.h"

int main(int argc, char const* argv[]) {
  // create context etc
  seal::EncryptionParameters parms(seal::scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(
      seal::CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

  double scale = pow(2.0, 40);

  seal::SEALContext context(parms);
  seal::KeyGenerator keygen(context);
  auto secret_key = keygen.secret_key();
  seal::PublicKey public_key;
  keygen.create_public_key(public_key);
  seal::RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);
  seal::GaloisKeys gal_keys;
  keygen.create_galois_keys(gal_keys);
  seal::Encryptor encryptor(context, public_key);
  seal::Evaluator evaluator(context);
  seal::Decryptor decryptor(context, secret_key);

  seal::CKKSEncoder encoder(context);
  seal::Plaintext plain_0, plain_1, plain_result;
  encoder.encode(std::vector<double>{2, 1, 34, 45}, scale, plain_0);
  std::vector<double> temp;
  encoder.decode(plain_0, temp);
  aluminum_shark::print_vector(temp, 10);
  std::cout << "scale " << plain_0.scale();
  encoder.encode(std::vector<double>{1, 2, 3, 4}, scale, plain_1);

  seal::Ciphertext ctxt_0, ctxt_1, ctxt_result;
  encryptor.encrypt(plain_0, ctxt_0);
  encryptor.encrypt(plain_1, ctxt_1);

  evaluator.add(ctxt_0, ctxt_1, ctxt_result);

  decryptor.decrypt(ctxt_result, plain_result);
  std::vector<double> decoded_result;
  encoder.decode(plain_result, decoded_result);
  for (size_t i = 0; i < 4; i++) {
    std::cout << decoded_result[i] << std::endl;
  }

  return 0;
}
