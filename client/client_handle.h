#ifndef aluminum_shark_client_client_handle_h 
#define aluminum_shark_client_client_handle_h

// #ifndef ALUMINUM_SHARK_DEPENDENCIES_TENSORFLOW_TENSORFLOW_COMPILER_PLUGIN_ALUMINUM_SHARK_PYTHON_PYTHON_HANDLE_H
// #define ALUMINUM_SHARK_DEPENDENCIES_TENSORFLOW_TENSORFLOW_COMPILER_PLUGIN_ALUMINUM_SHARK_PYTHON_PYTHON_HANDLE_H

#include <chrono>
#include <functional>
#include <list>
#include <map>
#include <queue>
#include<iostream>
#include <memory>
#include "tensorflow/compiler/plugin/aluminum_shark/he_backend/he_backend.h"
#include "tensorflow/compiler/plugin/aluminum_shark/logging.h"


// class ClientContext  {
//  public:
//   // Plugin API
//   virtual ~ClientContext() {
//     BACKEND_LOG << "Destroying Context " << reinterpret_cast<void*>(this)
//                 << std::endl;
//   };

#ifdef __cplusplus 
extern "C" { 
#endif

// Backend

// a light wrapper that is passed outside to python. it holds a shared_ptr ot
// the backend. this stuct is meant to be dynamically allocated and destyroyed
// via the python api belows
// typedef struct client_HEBackend {
//   std::shared_ptr<aluminum_shark::HEBackend> backend;
// };
typedef struct aluminum_shark_HEBackend {
  std::shared_ptr<aluminum_shark::HEBackend> backend;
};



// loads the hebackend shared library that is located in `libpath`.
//
// Returns: (void*)client_HEBackend*

void* client_loadBackend(const char* libpath);


// destroys the given `client_HEBackend`
void client_destroyBackend(void* backend_ptr);

// Context

// a light wrapper that is passed outside to python. it holds a shared_ptr ot
// the context. this stuct is meant to be dynamically allocated and destyroyed
// via the C api called from python
// typedef struct client_Context {
//   std::shared_ptr<aluminum_shark::HEContext> context;
// };

typedef struct aluminum_shark_Context {
  std::shared_ptr<aluminum_shark::HEContext> context;
};

// typedef struct aluminum_shark_Context {
//   std::shared_ptr<aluminum_shark::
//   SEAL_NODISCARD std::shared_ptr<const ContextData> seal::SEALContext::first_context_data() const
// };


// creates a new CKKS context using the backend specified by `backend_ptr` wich
// is a pointer to `client_HEBackend`. if the backend does not support
// the scheme this function returns a `nullptr`.
//
// - poly_modulus_degree (degree of polynomial modulus)
// - coeff_modulus ([ciphertext] coefficient modulus) list of moduli
// - size_coeff_modulus number of elements in the coeff_modulus array
// - plain_modulus (plaintext modulus)
//
// Returns (void*)client_Context*
void* client_CreateContextBFV(size_t poly_modulus_degree,
                                      const int* coeff_modulus,
                                      int size_coeff_modulus,
                                      size_t plain_modulus, void* backend_ptr);

// load and save the ContextBFV to and from files.
void client_SaveContextBFV(const char* file, void* backend_ptr);
void client_LoadContextBFV(const char* file, void* backend_ptr);


// creates a new CKKS context using the backend specified by `backend_ptr` wich
// is a pointer to `client_HEBackend`. if the backend does not support
// the scheme this function returns a `nullptr`.
//
// - size_coeff_modulus number of elements in the coeff_modulus array
//
// Returns (void*)client_Context*
void* client_CreateContextCKKS(size_t poly_modulus_degree,
                                       const int* coeff_modulus,
                                       int size_coeff_modulus, double scale,
                                       void* backend_ptr);

// load and save the ContextCKKS to and from files.
void client_SaveContext(const char* file, void* backend_ptr);
void client_LoadContextCKKS(const char* file, void* backend_ptr);

// creates a new TFHE context using the backend specified by `backend_ptr`
// wich is a pointer to `client_HEBackend`. if the backend does not
// support the scheme this function returns a `nullptr`.
//
// Returns (void*)client_Context*
// TODO: add support for this
void* client_CreateContextTFHE(void* backend_ptr);

// load and save the ContextTFHE to and from files.
void client_SaveContextTFHE(const char* file, void* backend_ptr);
void client_LoadContextTFHE(const char* file, void* backend_ptr);

// create keys. takes a `client*` which will hold a reference to
// the key
void client_CreatePublicKey(void* context_ptr);
void client_CreatePrivateKey(void* context_ptr);

// load and save the respective keys to and from files. takes a
// `client*` which holds a reference to the key
void client_SavePublicKey(const char* file, void* context_ptr);
void client_SavePrivateKey(const char* file, void* context_ptr);
void client_LoadPublicKey(const char* file, void* context_ptr);
void client_LoadPrivateKey(const char* file, void* context_ptr);

// saves the galvakeys and Relinkeys
void client_SaveContextGK(const char* file, void* context_ptr);
void client_SaveContextRK(const char* file, void* context_ptr);

// saves the encrpytion parameters
void client_SaveEncrpytionParameters(const char* file,void* context_ptr);

// void* client_LoadContext(const std::string path,aluminum_shark::HEContext* context_ptr,void* backend_ptr,double scale);

// Loads the galvakeys and Relinkeys
void client_LoadContextGK(const char* file, void* context_ptr);
void client_LoadContextRK(const char* file, void* context_ptr);

// Loads the encrpytion parameters
void client_LoadEncrpytionParameters(const char* file,void* context_ptr);

// get the number of slots supported by the context
size_t client_numberOfSlots(void* context_ptr);

// destory a context
void client_DestroyContext(void* context_ptr);

// Ciphertext

// a light wrapper that is passed outside to python. it holds a shared_ptr ot
// the ciphertext. this stuct is meant to be dynamically allocated and
// destyroyed via the python api belows
// typedef struct client_Ctxt {
//   std::shared_ptr<aluminum_shark::Ctxt> ctxt;
// };

typedef struct aluminum_shark_Ctxt {
  std::shared_ptr<aluminum_shark::HECtxt> ctxt;
};

size_t client_shark_GetCtxtShapeLen(void* ctxt_ptr);

void client_shark_GetCtxtShape(void* ctxt_ptr, size_t* shape_array);


// void* client_CreateCipher(void* ctxt_ptr);

// // load and save the ContextCKKS to and from files.
// void client_SaveCipher(const char* file, void* ctxt_ptr);
// void client_LoadCipher(const char* file, void* ctxt_ptr);

// destroy a ciphertext
void client_DestroyCiphertext(void* ctxt_ptr);

// create a cipher from the given input values using the context. this function
// dynamically allocates a `client_Ctxt`. the returned refrence needs
// to be cleaned up using `client_DestroyCiphertext`
//
// Returns: (void*)client_Ctxt*
void* client_CreateCipher(void* ctxt_ptr);

// load and save the Cipher to and from files.
void client_SaveCipher(const char* file, void* ctxt_ptr);
void client_LoadCipher(const char* file, void* ctxt_ptr);

void* client_encryptLong(const long* values, int size, const char* name,
                                 const size_t* shape, int shape_size,
                                 const char* layout, void* context_ptr);
void* client_encryptDouble(const double* values, int size,
                                   const char* name, const size_t* shape,
                                   int shape_size, const char* layout,
                                   void* context_ptr);


// decrypts the ctxt using the given context. the result will be written into a
// `client_List` struct. This function always decrypts the maximum
// number of slots supported by the scheme. The array pointed at by `ret` needs
// to have allocated memory for at least as many elements as the tensor size of
// the ciphertext. (the tensor size is the product of all dimensions of the
// shape)
void client_decryptLong(long* ret, void* ctxt_ptr, void* context_ptr);
void client_decryptDouble(double* ret, void* ctxt_ptr,
                                  void* context_ptr);

// // Glue code for passing data back and forth between python and c++

// // a light wrapper that is passed outside to python. it holds a shared_ptr to a
// // computation
// typedef struct client_Computation {
//   std::shared_ptr<client::ComputationHandle> computation;
// };

// // registert for the next computation
// void* client_RegisterComputation(void* (*ctxt_callback)(int*),
//                                          void (*result_callback)(void*, int),
//                                          const char* forced_layout);

// turns logging on or off
// void client_EnableLogging(bool on);

// sets the log level
void client_SetLogLevel(int level);

#ifdef __cplusplus
}
// extern "C"
#endif

#endif // aluminum_shark_client_client_handle_h 
