#ifndef ALUMINUM_SHARK_SEAL_BACKEND_BACKEND_H
#define ALUMINUM_SHARK_SEAL_BACKEND_BACKEND_H
#include <memory>
#include <string>

#include "he_backend/he_backend.h"
#include "seal/seal.h"

// this is the entry point to the backend
extern "C" {

std::shared_ptr<aluminum_shark::HEBackend> createBackend();

}  // extern "C"

namespace aluminum_shark {

class SEALBackend : public HEBackend {
 public:
  SEALBackend() : _version(API_VERSION()){};
  virtual ~SEALBackend(){};

  // Create an HEContect
  virtual HEContext* createContextBFV(size_t poly_modulus_degree,
                                      const std::vector<int>& coeff_modulus,
                                      size_t plain_modulus) override;
  virtual HEContext* createContextCKKS(size_t poly_modulus_degree,
                                       const std::vector<int>& coeff_modulus,
                                       double scale) override;

  virtual const std::string& name() override;
  virtual const std::string& to_string() override;
  virtual const API_VERSION& api_version() override;

  virtual void use_safe_masking(bool on_off) override;

  bool use_safe_masking() const;

 private:
  bool safe_masking = true;
  const API_VERSION _version;
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_BACKEND_H */
