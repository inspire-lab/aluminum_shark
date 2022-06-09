#include <memory>

#include "tensorflow/compiler/plugin/aluminum_shark/he_backend/he_backend.h"
#include "tensorflow/compiler/plugin/aluminum_shark/logging.h"

using namespace aluminum_shark;

int main(int argc, char const* argv[]) {
  // load backend
  std::shared_ptr<HEBackend> backend = loadBackend("../aluminum_shark_seal.so");
  // create context
  std::vector<int> coeff_modulus{60, 40, 40, 60};
  HEContext* context = backend->createContextCKKS(8192, coeff_modulus, 40);
  context->createPublicKey();
  context->createPrivateKey();

  // encrypte input
  std::vector<double> input1{35, 18, 6, 7};
  std::vector<double> input2{2, 2, 3, 3};
  HECtxt* ctxt1 = context->encrypt(input1, "x");
  HECtxt* ctxt2 = context->encrypt(input2, "y");
  // run the operation
  HECtxt* result = *ctxt1 - ctxt2;
  // Decrypt the result
  std::vector<double> res = context->decryptDouble(result);
  // Print out the vector
  std::cout << "v = { ";
  for (int n : res) {
    std::cout << n << ", ";
  }
  std::cout << "}; \n";

  /*--- tests can go here ---*/
}