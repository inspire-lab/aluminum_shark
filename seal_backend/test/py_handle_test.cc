#include <assert.h>
#include <stdlib.h>

#include <memory>
#include <string>
#include <vector>

#include "tensorflow/compiler/plugin/aluminum_shark/ctxt.h"
#include "tensorflow/compiler/plugin/aluminum_shark/he_backend/he_backend.h"
#include "tensorflow/compiler/plugin/aluminum_shark/logging.h"
#include "tensorflow/compiler/plugin/aluminum_shark/ptxt.h"
#include "tensorflow/compiler/plugin/aluminum_shark/python/python_handle.h"

using namespace aluminum_shark;

// we need this cause lambdas can't caputre and be converted to a function
// pointer
void* golabl_context;
std::vector<void*> global_ctxts;
std::vector<void*> global_results;

// since computaiton is approximate using CKKS we can't check for equality.
// instead we check if the result within a small tolarance
double tolarance = 0.01;

int main(int argc, char const* argv[]) {
  enable_logging(true);
  // load seal backend
  void* backend = aluminum_shark_loadBackend("../aluminum_shark_seal.so");
  // create context
  int coeff_modulus[] = {60, 40, 40, 60};
  golabl_context =
      aluminum_shark_CreateContextCKKS(8192, coeff_modulus, 4, 40, backend);
  AS_LOG_S << "Context: "
           << static_cast<aluminum_shark_Context*>(golabl_context)
                  ->context->to_string()
           << std::endl;
  size_t n_slots = aluminum_shark_numberOfSlots(golabl_context);
  // create keys
  aluminum_shark_CreatePrivateKey(golabl_context);
  aluminum_shark_CreatePublicKey(golabl_context);

  // encrypt
  // set up inputs
  double inputs1[] = {2, 1, 34, 45};
  size_t shape[] = {2, 2};
  void* ctxt_0 = aluminum_shark_encryptDouble(inputs1, 4, "x", shape, 2,
                                              "simple", golabl_context);
  double inputs2[] = {5, 4, 5, 10};
  void* ctxt_1 = aluminum_shark_encryptDouble(inputs2, 4, "y", shape, 2,
                                              "simple", golabl_context);

  // use the global vector so when can use them inside the lambda
  global_ctxts.push_back(ctxt_0);
  global_ctxts.push_back(ctxt_1);

  // create computation handle
  // we'll set up the ciphertexts inside the lambda
  void* comp_handle = aluminum_shark_RegisterComputation(
      // this is the callback would normally be called in python and allows the
      // python code to pass the ctxts handles to the computation
      [](int* no_ctxt) -> void* {
        *no_ctxt = global_ctxts.size();
        // oof
        void** ctxts = new void*[global_ctxts.size()];
        for (size_t i = 0; i < global_ctxts.size(); i++) {
          ctxts[i] = global_ctxts[i];
        }
        return ctxts;
      },
      // this is the callback would normally be called in python and return the
      // results of the computation
      [](void* result_ctxts, int no_ctxt) {
        for (size_t i = 0; i < no_ctxt; ++i) {
          global_results.push_back(((void**)result_ctxts)[i]);
        }
      });

  // check that we can retrieve the ciphertexts from the computation handle
  aluminum_shark_Computation* computation =
      reinterpret_cast<aluminum_shark_Computation*>(comp_handle);
  std::vector<Ctxt> ctxts = computation->computation->getCiphertTexts();
  for (auto& c : ctxts) {
    std::cout << "retrieved ctxts from computation handle " << c.getName()
              << std::endl;
  }
  assert(ctxts[0].getName() == "x");
  assert(ctxts[1].getName() == "y");

  // perform computation
  auto mult_result = ctxts[0] * ctxts[1];
  auto add_result = ctxts[0] + ctxts[1];

  // create result vector
  // get the raw pointer held by the shared_ptr and cast it to Ctxt*, then
  // derference it
  std::vector<Ctxt> results{*(dynamic_cast<Ctxt*>(mult_result.get())),
                            *(dynamic_cast<Ctxt*>(add_result.get()))};
  computation->computation->transfereResults(results);

  // now the results should be in the global vector
  void* ctxt_handle_mult = global_results[0];
  void* ctxt_handle_add = global_results[1];

  // decrypt and check the results
  // multiplication first
  // determine shape to allocate memory
  size_t shape_len = aluminum_shark_GetCtxtShapeLen(ctxt_handle_mult);
  size_t* shape0 = new size_t[shape_len];
  aluminum_shark_GetCtxtShape(ctxt_handle_mult, shape0);
  size_t size = 1;
  for (size_t i = 0; i < shape_len; i++) {
    size *= shape0[i];
  }
  // allocate memory for decryption
  double* decrypted = new double[size];

  // decrypt
  aluminum_shark_decryptDouble(decrypted, ctxt_handle_mult, golabl_context);
  std::cout << "decrypted after multiplication ";
  for (size_t i = 0; i < size; i++) {
    std::cout << decrypted[i] << ", ";
  }
  std::cout << std::endl;
  for (size_t i = 0; i < size; i++) {
    std::cout << "decrypted: " << decrypted[i]
              << ", expected: " << inputs1[i] * inputs2[i] << std::endl;
    assert(decrypted[i] - (inputs1[i] * inputs2[i]) < tolarance);
  }
  // clean up
  delete[] shape0;
  delete[] decrypted;
  aluminum_shark_DestroyCiphertext(ctxt_handle_mult);

  // addition next first
  // determine shape to allocate memory
  shape_len = aluminum_shark_GetCtxtShapeLen(ctxt_handle_add);
  shape0 = new size_t[shape_len];
  aluminum_shark_GetCtxtShape(ctxt_handle_add, shape0);
  size = 1;
  for (size_t i = 0; i < shape_len; i++) {
    size *= shape0[i];
  }
  // allocate memory for decryption
  decrypted = new double[size];

  // decrypt
  aluminum_shark_decryptDouble(decrypted, ctxt_handle_add, golabl_context);
  std::cout << "decrypted after addition ";
  for (size_t i = 0; i < size; i++) {
    std::cout << decrypted[i] << ", ";
  }
  std::cout << std::endl;
  for (size_t i = 0; i < size; i++) {
    std::cout << "decrypted: " << decrypted[i]
              << ", expected: " << inputs1[i] + inputs2[i] << std::endl;
    assert(decrypted[i] - (inputs1[i] + inputs2[i]) < tolarance);
  }
  std::cout << std::endl;
  // clean up
  delete[] shape0;
  delete[] decrypted;
  aluminum_shark_DestroyCiphertext(ctxt_handle_add);

  // clean up
  for (void* handle : global_ctxts) {
    aluminum_shark_DestroyCiphertext(handle);
  };
  aluminum_shark_DestroyContext(golabl_context);
  aluminum_shark_destroyBackend(backend);

  // return 0;
}
