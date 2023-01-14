
#include "backend.h"

#include "context.h"
#include "logging.h"
#include "python/arg_utils.h"
#include "seal/seal.h"

// this is the entry point to the backend
extern "C" {

std::shared_ptr<aluminum_shark::HEBackend> createBackend() {
  std::shared_ptr<aluminum_shark::HEBackend> ptr(
      new aluminum_shark::SEALBackend());
  return ptr;
}
}  // extern "C"

namespace {
const std::string BACKEND_NAME = "SEAL Backend";
const seal::SEALVersion sv;
const std::string BACKEND_STRING =
    BACKEND_NAME + " using SEAL " + std::to_string(sv.major) + "." +
    std::to_string(sv.minor) + "." + std::to_string(sv.patch);

}  // namespace

namespace aluminum_shark {

HEContext* SEALBackend::createContextBFV(size_t poly_modulus_degree,
                                         const std::vector<int>& coeff_modulus,
                                         size_t plain_modulus) {
  // setup the encryption parameters
  seal::EncryptionParameters params(seal::scheme_type::bfv);
  params.set_poly_modulus_degree(poly_modulus_degree);
  // in BFV we can get a default value. indicated by a 0.
  // TODO: refactor that out into a different case?
  if (coeff_modulus[0] == 0) {
    params.set_coeff_modulus(
        seal::CoeffModulus::BFVDefault(poly_modulus_degree));
  } else {
    params.set_coeff_modulus(
        seal::CoeffModulus::Create(poly_modulus_degree, coeff_modulus));
  }
  params.set_plain_modulus(plain_modulus);
  SEALContext* context_ptr = new SEALContext(seal::SEALContext(params), *this);
  return context_ptr;
}

HEContext* SEALBackend::createContextCKKS(size_t poly_modulus_degree,
                                          const std::vector<int>& coeff_modulus,
                                          double scale) {
  // setup the encryption parameters
  seal::EncryptionParameters params(seal::scheme_type::ckks);
  params.set_poly_modulus_degree(poly_modulus_degree);
  params.set_coeff_modulus(
      seal::CoeffModulus::Create(poly_modulus_degree, coeff_modulus));

  SEALContext* context_ptr =
      new SEALContext(seal::SEALContext(params), *this, scale);
  return context_ptr;
}

HEContext* SEALBackend::createContextCKKS(
    std::vector<aluminum_shark_Argument> arguments) {
  AS_LOG_INFO << "Creating Context. Arguments\n"
              << args_to_string(arguments) << std::endl;

  size_t poly_modulus_degree = 0;
  std::vector<int> coeff_modulus;
  double scale = -1;

  for (const aluminum_shark_Argument& arg : arguments) {
    const char* name = arg.name;
    AS_LOG_DEBUG << "Processing argument: " << name << " type: " << arg.type
                 << " is_ array: " << arg.is_array << std::endl;
    if (std::strcmp(name, "poly_modulus_degree") == 0) {
      if (arg.type != 0 || arg.array_) {
        AS_LOG_CRITICAL << name << " needs to be scalar int" << std::endl;
      }
      poly_modulus_degree = arg.int_;
      continue;
    } else if (std::strcmp(name, "scale") == 0) {
      if (arg.type != 1 || arg.array_) {
        AS_LOG_CRITICAL << name << " needs to be scalar doulbe" << std::endl;
      }
      scale = arg.double_;
      continue;
    } else if (std::strcmp(name, "coeff_modulus") == 0) {
      if (arg.type != 0 || !arg.array_) {
        AS_LOG_CRITICAL << name << " needs to be int array" << std::endl;
      }
      long* arr = reinterpret_cast<long*>(arg.array_);
      for (size_t i = 0; i < arg.size_; i++) {
        coeff_modulus.push_back(arr[i]);
      }
      continue;
    }
  }

  if (poly_modulus_degree == 0 || coeff_modulus.size() == 0 || scale == -1) {
    AS_LOG_CRITICAL << "missing parameter" << std::endl;
    throw std::runtime_error("missing parameter");
  }
  return createContextCKKS(poly_modulus_degree, coeff_modulus, scale);
}

const std::string& SEALBackend::name() { return BACKEND_NAME; }
const std::string& SEALBackend::to_string() { return BACKEND_STRING; }
const API_VERSION& SEALBackend::api_version() { return _version; }

}  // namespace aluminum_shark