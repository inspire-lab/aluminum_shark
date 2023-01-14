#ifndef ALUMINUM_SHARK_OPENFHE_BACKEND_BACKEND_H
#define ALUMINUM_SHARK_OPENFHE_BACKEND_BACKEND_H

#include <memory>
#include <string>

#include "he_backend/he_backend.h"
#include "openfhe.h"

// this is the entry point to the backend
extern "C" {

std::shared_ptr<aluminum_shark::HEBackend> createBackend();

}  // extern "C"
namespace aluminum_shark {

class OpenFHEBackend : public HEBackend {
 public:
  OpenFHEBackend() : version_(API_VERSION()){};
  virtual ~OpenFHEBackend(){};

  // Create an HEContect
  virtual HEContext* createContextBFV(size_t poly_modulus_degree,
                                      const std::vector<int>& coeff_modulus,
                                      size_t plain_modulus) override;
  virtual HEContext* createContextCKKS(size_t poly_modulus_degree,
                                       const std::vector<int>& coeff_modulus,
                                       double scale) override;

  virtual HEContext* createContextCKKS(
      std::vector<aluminum_shark_Argument> arguments) override;

  virtual const std::string& name() override;
  virtual const std::string& to_string() override;
  virtual const API_VERSION& api_version() override;

 private:
  const API_VERSION version_;
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_OPENFHE_BACKEND_BACKEND_H */