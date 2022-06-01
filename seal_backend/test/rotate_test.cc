#include <cmath>
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

//Rotate inPlace operation Test

  // encrypte input
  int steps = -3;  // steps to rotate
  std::vector<double> input1{35, 18, 6, 7};
  HECtxt* ctxt1 = context->encrypt(input1, "x");
  HECtxt* ctxt2 = ctxt1->deepCopy();
  // Decrypt and Show before the rotating
  std::vector<double> before = context->decryptDouble(ctxt2);

  // run the operation
  ctxt1->rotInPlace(steps);
  // Decrypt the result
  std::vector<double> result = context->decryptDouble(ctxt1);
  // Iterate over the results and check if it rotated correctly
  bool flag = true;
  for (size_t i = 0; i < result.size(); ++i) {
    if (std::fabs(before[(i + steps) % before.size()] - result[i]) > 0.001) {
      std::cout << std::fabs(before[(i + steps) % before.size()] - result[i])
                << std::endl;
      std::cout << "rotate operation was not performed correctly\n";
      std::cout << result[i] << " and before "
                << before[(i + steps) % before.size()] << std::endl;
      flag = false;
      break;
    }
  }
  if (flag == true) {
    std::cout << "rotate inPlace operation was performed correctlly\n";
  }

//Rotate operation Test

  steps = 5;
  std::vector<double> input2{42, 15, 16, 23};
  HECtxt* ctxt3 = context->encrypt(input2, "z");
  HECtxt* ctxt4 = ctxt3->deepCopy();
  // Decrypt and Show before the rotating
  std::vector<double> before1 = context->decryptDouble(ctxt4);

  // run the operation
  HECtxt* res = ctxt3->rotate(steps);
  // Decrypt the result
  std::vector<double> result1 = context->decryptDouble(res);
  // Iterate over the results and check if it rotated correctly
  flag = true;
  for (size_t j = 0; j < result1.size(); ++j) {
    if (std::fabs(before1[(j + steps) % before1.size()] - result1[j]) > 0.001) {
      std::cout << std::fabs(before1[(j + steps) % before1.size()] - result1[j])
                << std::endl;
      std::cout << "rotate operation was not performed correctly\n";
      std::cout << result1[j] << " and before "
                << before1[(j + steps) % before1.size()] << std::endl;
      flag = false;
      break;
    }
  }
  if (flag == true) {
    std::cout << "rotate operation was performed correctlly\n";
  }

  /*--- tests can go here ---*/
}

// std::cout << "before = { ";
// for (int n : before) {
//       std::cout << n << ", ";
//   }
//   std::cout << "}; \n";