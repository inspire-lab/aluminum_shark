
#include "backend.h"

#include <cstring>
#include <iostream>
#include <stdexcept>

#include "context.h"
#include "logging.h"
#include "openfhe.h"
#include "python/arg_utils.h"

// this is the entry point to the backend
extern "C" {

std::shared_ptr<aluminum_shark::HEBackend> createBackend() {
  aluminum_shark::set_log_prefix("OpenFHE Backend");
  AS_LOG_INFO << " Creating OpenFHEBackend " << std::endl;
  std::shared_ptr<aluminum_shark::HEBackend> ptr =
      std::make_unique<aluminum_shark::OpenFHEBackend>();
  AS_LOG_INFO << " Created OpenFHEBackend " << std::endl;
  return ptr;
}
}  // extern "C"

namespace {
const std::string BACKEND_NAME = "OpenFHE Backend";
const std::string BACKEND_STRING = BACKEND_NAME;
// BACKEND_NAME + " using OpenFHE " + OpenFHEBackend();

}  // namespace
namespace aluminum_shark {

HEContext* OpenFHEBackend::createContextBFV(
    size_t poly_modulus_degree, const std::vector<int>& coeff_modulus,
    size_t plain_modulus) {
  AS_LOG_CRITICAL << "BFV currently not implemented for OpenFHE" << std::endl;
  throw std::runtime_error("not implemented");
}

HEContext* OpenFHEBackend::createContextCKKS(
    size_t poly_modulus_degree, const std::vector<int>& coeff_modulus,
    double scale) {
  AS_LOG_CRITICAL
      << "Use the dynamic argument function to create a CKKS context."
      << std::endl;
  throw std::runtime_error("not implemented");
}

HEContext* OpenFHEBackend::createContextCKKS(
    std::vector<aluminum_shark_Argument> arguments) {
  // setup the encryption parameters
  AS_LOG_INFO << "Creating Context. Arguments\n"
              << args_to_string(arguments) << std::endl;
  lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> params;
  for (const aluminum_shark_Argument& arg : arguments) {
    const char* name = arg.name;
    AS_LOG_DEBUG << "Processing argument: " << name << " type: " << arg.type
                 << " is_ array: " << arg.is_array << std::endl;
    if (std::strcmp(name, "multiplicative_depth") == 0) {
      if (arg.type != 0 || arg.array_) {
        AS_LOG_CRITICAL << name << " needs to be scalar int" << std::endl;
      }
      params.SetMultiplicativeDepth(arg.int_);
      continue;
    } else if (std::strcmp(name, "scaling_mod_size") == 0) {
      if (arg.type != 0 || arg.array_) {
        AS_LOG_CRITICAL << name << " needs to be scalar int" << std::endl;
      }
      params.SetScalingModSize(arg.int_);
      continue;
    } else if (std::strcmp(name, "batch_size") == 0) {
      if (arg.type != 0 || arg.array_) {
        AS_LOG_CRITICAL << name << " needs to be scalar int" << std::endl;
      }
      params.SetBatchSize(arg.int_);
      continue;
    } else if (std::strcmp(name, "ring_dim") == 0) {
      if (arg.type != 0 || arg.array_) {
        AS_LOG_CRITICAL << name << " needs to be scalar int" << std::endl;
      }
      params.SetRingDim(arg.int_);
      continue;
    }
  }
  params.SetScalingTechnique(ScalingTechnique::FLEXIBLEAUTO);
  params.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);

  auto context = lbcrypto::GenCryptoContext(params);

  context->Enable(PKESchemeFeature::PKE);
  context->Enable(PKESchemeFeature::KEYSWITCH);
  context->Enable(PKESchemeFeature::LEVELEDSHE);

  return new OpenFHEContext(context, *this);
}

const std::string& OpenFHEBackend::name() { return BACKEND_NAME; }
const std::string& OpenFHEBackend::to_string() { return BACKEND_STRING; }
const API_VERSION& OpenFHEBackend::api_version() { return version_; }

void OpenFHEBackend::set_log_level(int level) {
  ::aluminum_shark::set_log_level(level);
}

// monitor stuff
const std::vector<std::string> OpenFHEMonitor::supported_values;

}  // namespace aluminum_shark