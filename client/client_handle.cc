#include "client_handle.h"
#include <chrono>
#include <cstring>
#include <functional>
#include <list>
#include <map>
#include <queue>
#include <vector>
#include <iostream>
#include <filesystem>
#include <fstream>

#include <string>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>
#include <exception>


// need as reverse mapping to return the context handle when the ctxt result is
// retrieved
static std::map<const aluminum_shark::HEContext*, aluminum_shark_Context*>
    context_map;
 

extern "C" {
void* client_loadBackend(const char* libpath)
{
   
std::shared_ptr<aluminum_shark::HEBackend> test=aluminum_shark::loadBackend(libpath);
aluminum_shark_HEBackend *obj=new aluminum_shark_HEBackend();
obj->backend=test;
return obj;
  
}

void client_destroyBackend(void* backend_ptr) {
  delete static_cast<aluminum_shark_HEBackend*>(backend_ptr);
}


// Key management

void client_CreatePublicKey(void* context_ptr) {
  AS_LOG_S<<"Creating pubkey; context " << context_ptr << std::endl;
  static_cast<aluminum_shark_Context*>(context_ptr)->context->createPublicKey();
  AS_LOG("Created pubkey");
}
}
void client_CreatePrivateKey(void* context_ptr) {
  AS_LOG_S << "Creating private key; context " << context_ptr << std::endl;
  static_cast<aluminum_shark_Context*>(context_ptr)->context->createPrivateKey();
  AS_LOG("Created private key");
}
void client_SavePrivateKey(const char* file, void* context_ptr) {
  // AS_LOG("SavePrivateKey not implemented");
  static_cast<aluminum_shark_Context*>(context_ptr)->context->savePrivateKey(file);
  AS_LOG("SavePrivateKey implemented");
}

void client_SavePublicKey(const char* file, void* context_ptr) {
  std::cout << file << std::endl;
  static_cast<aluminum_shark_Context*>(context_ptr)->context->savePublicKey(file);
  AS_LOG("SavePublicKey implemented"); 
}
void client_LoadPublicKey(const char* file, void* context_ptr) {
  static_cast<aluminum_shark_Context*>(context_ptr)->context->loadPublicKey(file);
  AS_LOG("LoadPublicKey  implemented");
}
void client_LoadPrivateKey(const char* file, void* context_ptr) {
  static_cast<aluminum_shark_Context*>(context_ptr)->context->loadPrivateKey(file);
  AS_LOG("LoadPrivateKey implemented");
}

void client_SaveContextGK(const char* file, void* context_ptr) {
static_cast<aluminum_shark_Context*>(context_ptr)->context->SaveContextGK(file);                                      
AS_LOG("Saving Context Galoiskey implemented");
}

void client_SaveContextRK(const char* file, void* context_ptr) {
static_cast<aluminum_shark_Context*>(context_ptr)->context->SaveContextRK(file);                                      
AS_LOG("Saving Context Relinkeys implemented");
}

void client_SaveEncrpytionParameters(const char* file,void* context_ptr) {
static_cast<aluminum_shark_Context*>(context_ptr)->context->SaveEncryptionParameters(file);                                      
AS_LOG("Saving Encryption Parameters implemented");
}

void client_LoadContextGK(const char* file, void* context_ptr) {
static_cast<aluminum_shark_Context*>(context_ptr)->context->LoadContextGK(file);                                      
AS_LOG("Loading Galoiskey implemented");
}

void client_LoadContextRK(const char* file, void* context_ptr) {
static_cast<aluminum_shark_Context*>(context_ptr)->context->LoadContextRK(file);                                      
AS_LOG("Loading Relinkeys implemented");
}

void client_LoadEncrpytionParameters(const char* file,void* context_ptr) {
static_cast<aluminum_shark_Context*>(context_ptr)->context->LoadEncryptionParameters(file);                                      
AS_LOG("Loading Encryption Parameters implemented");
}

                              
void* client_CreateContextCKKS(size_t poly_modulus_degree,
                                       const int* coeff_modulus,
                                       int size_coeff_modulus, double scale,
                                       void* backend_ptr) {
  AS_LOG("creating CKKS backend");
  std::vector<int> coeff_modulus_vec(coeff_modulus,
                                     coeff_modulus + size_coeff_modulus);
  AS_LOG_S << "poly_modulus_degree " << std::to_string(poly_modulus_degree)
           << " coeff_modulus [";
  for (auto v : coeff_modulus_vec) {
    AS_LOG_SA << std::to_string(v) << ",";
  }
  AS_LOG_SA << "], scale " << std::to_string(scale)
           << " backend pointer: " << backend_ptr << std::endl;
  aluminum_shark_HEBackend* as_backend =
      static_cast<aluminum_shark_HEBackend*>(backend_ptr);
  AS_LOG_S << "cast successful " << reinterpret_cast<void*>(as_backend)
           << std::endl;
  std::shared_ptr<aluminum_shark::HEBackend> backend = as_backend->backend;
  AS_LOG_S << "backend " << backend << std::endl;
  aluminum_shark_Context* ret = new aluminum_shark_Context();
  ret->context =
      std::shared_ptr<aluminum_shark::HEContext>(backend->createContextCKKS(
          poly_modulus_degree,
          std::vector<int>(coeff_modulus, coeff_modulus + size_coeff_modulus),
          scale));
  AS_LOG_S << "Created new Context: " << reinterpret_cast<void*>(as_backend)
           << "wrappend context " << ret->context << std::endl;
  context_map[ret->context.get()] = ret;
  return ret;
}


// void* client_LoadContext(const std::string path,void* backend_ptr,double scale) {


// aluminum_shark_HEBackend* as_backend =
//       static_cast<aluminum_shark_HEBackend*>(backend_ptr);
//   std::shared_ptr<aluminum_shark::HEBackend> backend = as_backend->backend;

//  aluminum_shark_Context* ret = new aluminum_shark_Context();
//   ret->context =
//       std::shared_ptr<aluminum_shark::HEContext>(backend->loadContext(
//           path,
//           scale));

//   context_map[ret->context.get()] = ret;
//   AS_LOG("Loading context implemented");
//   return ret;

// }

// void client_LoadPrivateKey(const char* file, void* context_ptr)
// static_cast<aluminum_shark_Context*>(context_ptr)->context->SaveContextCKKS(file);                                      
// AS_LOG("saving CKKS context");
                                       


 // extern c