#ifndef ALUMINUM_SHARK_SEAL_BACKEND_BACKEND_H
#define ALUMINUM_SHARK_SEAL_BACKEND_BACKEND_H
#include <memory>
#include <string>
#include <vector>

#include "he_backend/he_backend.h"
#include "seal/seal.h"

// this is the entry point to the backend
extern "C" {

std::shared_ptr<aluminum_shark::HEBackend> createBackend();

}  // extern "C"

namespace aluminum_shark {

class SEALMonitor : public Monitor {
 public:
  // retrieves the value specified by name and writes it into value, returns
  // false if the value is not logged or unsoproted;
  virtual bool get(const std::string& name, double& value) override;

  // can be used to iterate over all logged valued by this monitor. puts the
  // name of the value into `name` and the value into `value`. Returns false if
  // there are no more values. Calling it again after that restarts
  virtual bool get_next(std::string& name, double& value) override;

  // returns a list of all values supported by this monitor
  virtual const std::vector<std::string>& values() override;

  static std::shared_ptr<SEALMonitor> instance;

 private:
  static std::vector<std::string> supported_values;
  size_t _count = 0;
  // helper. the value_no needs to cooresponds to the index in
  // SEALMonitor::supported_values
  bool get_monitor_value(size_t value_no, double& value);
};

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

  virtual HEContext* createContextCKKS(
      std::vector<aluminum_shark_Argument> arguments) override;

  virtual const std::string& name() override;
  virtual const std::string& to_string() override;
  virtual const API_VERSION& api_version() override;

  virtual void set_log_level(int level) override;

  virtual std::shared_ptr<Monitor> enable_ressource_monitor(
      bool) const override;
  virtual std::shared_ptr<Monitor> get_ressource_monitor() const override {
    return SEALMonitor::instance;
  };

 private:
  const API_VERSION _version;
  std::shared_ptr<SEALMonitor> _monitor;
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_BACKEND_H */
