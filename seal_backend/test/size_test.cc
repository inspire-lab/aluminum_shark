#include <assert.h>
#include <stdlib.h>

#include <fstream>
#include <memory>
#include <string>

#include "seal/seal.h"
#include "utils/utils.h"

size_t ptxt_size(seal::SEALContext& context, seal::Plaintext& ptxt) {
  // time to calculate the size
  // size of the coefficient modulus (number of primes) times the degree of the
  // polynomial modulus.
  auto parms = context.get_context_data(ptxt.parms_id())->parms();
  std::size_t coeff_modulus_size = parms.coeff_modulus().size();
  std::size_t poly_modulus_degree = parms.poly_modulus_degree();
  return coeff_modulus_size * poly_modulus_degree * 8;
}

size_t ctxt_size(seal::SEALContext& context, seal::Ciphertext& ctxt) {
  // see: https://github.com/microsoft/SEAL/issues/88#issuecomment-564342477
  auto context_data = context.get_context_data(ctxt.parms_id());
  size_t size = ctxt.size();
  size *= context_data->parms().coeff_modulus().size();
  size *= context_data->parms().poly_modulus_degree();
  size *= 8;
  return size;
}

int main(int argc, char const* argv[]) {
  //   crypto_config = {  # depth esititmate: 19
  //     'poly_modulus_degree': 32768,
  //     'coeff_modulus': [
  //         40, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
  //         30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 40
  //     ],
  //     'scale': 30.0,
  //     'multiplicative_depth': 19
  // }
  // create context etc
  std::cout << "creating context" << std::endl;
  seal::EncryptionParameters parms(seal::scheme_type::ckks);
  // size_t poly_modulus_degree = 32768;
  // std::vector<int> bit_sizes{40, 30, 30, 30, 30, 30, 30, 30, 30, 30,
  //                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
  //                            30, 30, 30, 30, 30, 30, 30, 40};

  size_t poly_modulus_degree = 16384;
  std::vector<int> bit_sizes{40, 20, 20, 40};

  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(
      seal::CoeffModulus::Create(poly_modulus_degree, bit_sizes));

  double scale = pow(2.0, bit_sizes[1]);

  seal::SEALContext context(parms);

  std::cout << "creating keys" << std::endl;
  seal::KeyGenerator keygen(context);
  auto secret_key = keygen.secret_key();
  seal::PublicKey public_key;
  keygen.create_public_key(public_key);
  seal::RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);

  seal::Encryptor encryptor(context, public_key);
  seal::Evaluator evaluator(context);
  seal::Decryptor decryptor(context, secret_key);

  std::cout << "encoding" << std::endl;
  seal::CKKSEncoder encoder(context);
  seal::Plaintext plain_0;
  encoder.encode(std::vector<double>(poly_modulus_degree / 2, 1), scale,
                 plain_0);

  std::cout << "encrypting" << std::endl;
  seal::Ciphertext ctxt_0;
  encryptor.encrypt(plain_0, ctxt_0);

  // // save plaintext
  // std::cout << "saving ptxt" << std::endl;
  // std::ofstream ptxt_stream("plaintext.bin", std::ios::binary);
  // plain_0.save(ptxt_stream, seal::compr_mode_type::none);
  // ptxt_stream.close();

  // std::cout << "saving ctxt" << std::endl;
  // std::ofstream ctxt_stream("ciphertext.bin", std::ios::binary);
  // ctxt_0.save(ctxt_stream, seal::compr_mode_type::none);
  // ctxt_stream.close();

  float last_ctxt_size = 0;

  for (size_t i = 0; i < bit_sizes.size() - 2; i++) {
    encoder.encode(std::vector<double>(poly_modulus_degree / 2, 1),
                   ctxt_0.parms_id(), ctxt_0.scale(), plain_0);
    float csize =
        static_cast<float>(ctxt_size(context, ctxt_0));  // /  1024 / 1024;
    float psize =
        static_cast<float>(ptxt_size(context, plain_0));  // / 1024 / 1024;
    std::cout << "level: " << i << std::endl;
    std::cout << "\tctxt:  " << csize << " bytes";
    if (i != 0) {
      std::cout << " (" << last_ctxt_size - csize << ")";
    }
    std::cout << std::endl;
    std::cout << "\tptxt:  " << psize << " bytes" << std::endl;
    std::cout << "\tratio: " << csize / psize << std::endl;
    evaluator.multiply_plain_inplace(ctxt_0, plain_0);
    evaluator.relinearize_inplace(ctxt_0, relin_keys);
    evaluator.rescale_to_next_inplace(ctxt_0);
    last_ctxt_size = csize;

    // ctxt_stream = std::ofstream("ciphertext_" + std::to_string(i) + ".bin",
    //                             std::ios::binary);
    // ctxt_0.save(ctxt_stream, seal::compr_mode_type::none);
    // ctxt_stream.close();

    // ptxt_stream = std::ofstream("plaintext_" + std::to_string(i) + ".bin",
    //                             std::ios::binary);
    // plain_0.save(ptxt_stream, seal::compr_mode_type::none);
    // ptxt_stream.close();
  }

  return 0;
}
