#include <assert.h>
#include <stdlib.h>

#include <memory>
#include <string>

#include "tensorflow/compiler/plugin/aluminum_shark/ctxt.h"
#include "tensorflow/compiler/plugin/aluminum_shark/he_backend/he_backend.h"
#include "tensorflow/compiler/plugin/aluminum_shark/logging.h"
#include "tensorflow/compiler/plugin/aluminum_shark/ptxt.h"
#include "tensorflow/compiler/plugin/aluminum_shark/python/python_handle.h"

using namespace aluminum_shark;

int main(int argc, char const* argv[]) {
  enable_logging(true);
  // load seal backend
  void* backend = aluminum_shark_loadBackend("../aluminum_shark_seal.so");
  // create context
  int coeff_modulus[] = {60, 40, 40, 60};
  void* context =
      aluminum_shark_CreateContextCKKS(8192, coeff_modulus, 4, 40, backend);
  AS_LOG_S
      << "Context: "
      << static_cast<aluminum_shark_Context*>(context)->context->to_string()
      << std::endl;
  size_t n_slots = aluminum_shark_numberOfSlots(context);
  // create keys
  aluminum_shark_CreatePrivateKey(context);
  aluminum_shark_CreatePublicKey(context);
  // auto context_wrapper = static_cast<aluminum_shark_Context*>(context);
  // auto he_context = context_wrapper->context;
  // he_context->createPrivateKey();
  // encrypt
  double inputs[] = {2, 1, 34, 45};
  void* ctxt_0 = aluminum_shark_encryptDouble(inputs, 4, "x", context);
  // check that encryption and decrypion works
  double* decrypted = new double[n_slots];
  int return_size;
  aluminum_shark_decryptDouble(decrypted, &return_size, ctxt_0, context);
  std::cout << "decrypted values: ";
  for (size_t i = 0; i < 5; i++) {
    std::cout << decrypted[i] << ", ";
  }
  std::cout << std::endl;

  delete[] decrypted;

  double input_1[] = {1, 2, 3, 4};
  void* ctxt_1 = aluminum_shark_encryptDouble(input_1, 4, "y", context);
  // set values
  void* ctxts[] = {ctxt_0, ctxt_1};
  aluminum_shark_SetChipherTexts(ctxts, 2);

  // get values
  PythonHandle& pyh = PythonHandle::getInstance();
  auto ciphertexts = pyh.getCurrentCiphertexts();

  BaseTxt& x = ciphertexts[0];
  BaseTxt& y = ciphertexts[1];

  std::shared_ptr<BaseTxt> result = x * x;
  Ctxt& ctxt_ref = dynamic_cast<Ctxt&>(*result);
  pyh.setCurrentResult(ctxt_ref);

  void* context_ptr;
  void* ctxt_result = aluminum_shark_GetChipherTextResult(&context_ptr);
  assert(context_ptr == context);
  n_slots = aluminum_shark_numberOfSlots(context_ptr);
  // allocated return buffer
  decrypted = new double[n_slots];
  int ret_size = -1;
  aluminum_shark_decryptDouble(decrypted, &ret_size, ctxt_result, context_ptr);
  std::cout << "decrypted values: ";
  for (size_t i = 0; i < 5; i++) {
    std::cout << decrypted[i] << ", ";
  }
  std::cout << std::endl;
  // clean up
  delete[] decrypted;
  aluminum_shark_DestroyCiphertext(ctxt_0);
  aluminum_shark_DestroyCiphertext(ctxt_1);
  aluminum_shark_DestroyCiphertext(ctxt_result);
  aluminum_shark_DestroyContext(context);
  aluminum_shark_destroyBackend(backend);

  return 0;
}
