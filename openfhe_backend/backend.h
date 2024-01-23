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

// not fully implemented. does nothhing atm
class OpenFHEMonitor : public Monitor {
 public:
  // retrieves the value specified by name and writes it into value, returns
  // false if the value is not logged or unsoproted;
  bool get(const std::string& name, double& value) override { return false; };

  // can be used to iterate over all logged valued by this monitor. puts the
  // name of the value into `name` and the value into `value`. Returns false if
  // there are no more values. Calling it again after that restarts
  bool get_next(std::string& name, double& value) override { return false; };

  // returns a list of all values supported by this monitor
  const std::vector<std::string>& values() override {
    return supported_values;
  };

 private:
  static const std::vector<std::string> supported_values;
};

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

  virtual void set_log_level(int level) override;

  std::shared_ptr<Monitor> enable_ressource_monitor(
      bool enable) const override {
    return std::make_shared<OpenFHEMonitor>();
  };

  std::shared_ptr<Monitor> get_ressource_monitor() const override {
    return std::make_shared<OpenFHEMonitor>();
  };
  ;

 private:
  const API_VERSION version_;
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_OPENFHE_BACKEND_BACKEND_H */
