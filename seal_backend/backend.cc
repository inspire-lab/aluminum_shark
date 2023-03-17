
#include "backend.h"

#include "context.h"
#include "ctxt.h"
#include "logging.h"
#include "python/arg_utils.h"
#include "seal/seal.h"

// this is the entry point to the backend
extern "C" {

std::shared_ptr<aluminum_shark::HEBackend> createBackend() {
  std::shared_ptr<aluminum_shark::HEBackend> ptr(
      new aluminum_shark::SEALBackend());
  aluminum_shark::set_log_prefix("SEAL Backend");
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

HEContext* SEALBackend::createContextCKKS_internal(
    size_t poly_modulus_degree, const std::vector<int>& coeff_modulus,
    double scale, bool galois_keys) {
  // setup the encryption parameters
  seal::EncryptionParameters params(seal::scheme_type::ckks);
  params.set_poly_modulus_degree(poly_modulus_degree);
  params.set_coeff_modulus(
      seal::CoeffModulus::Create(poly_modulus_degree, coeff_modulus));

  SEALContext* context_ptr =
      new SEALContext(seal::SEALContext(params), *this, scale, galois_keys);
  return context_ptr;
}

HEContext* SEALBackend::createContextCKKS(size_t poly_modulus_degree,
                                          const std::vector<int>& coeff_modulus,
                                          double scale) {
  return createContextCKKS_internal(poly_modulus_degree, coeff_modulus, scale);
}

HEContext* SEALBackend::createContextCKKS(
    std::vector<aluminum_shark_Argument> arguments) {
  AS_LOG_INFO << "Creating Context. Arguments\n"
              << args_to_string(arguments) << std::endl;

  size_t poly_modulus_degree = 0;
  std::vector<int> coeff_modulus;
  double scale = -1;
  bool galois_keys = true;

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
    } else if (std::strcmp(name, "galois_keys") == 0) {
      if (arg.type != 0 || arg.array_) {
        AS_LOG_CRITICAL << name << " needs to be scalar int" << std::endl;
      }
      galois_keys = arg.int_ != 0;
      continue;
    }
  }

  if (poly_modulus_degree == 0 || coeff_modulus.size() == 0 || scale == -1) {
    AS_LOG_CRITICAL << "missing parameter" << std::endl;
    throw std::runtime_error("missing parameter");
  }
  return createContextCKKS_internal(poly_modulus_degree, coeff_modulus, scale,
                                    galois_keys);
}

const std::string& SEALBackend::name() { return BACKEND_NAME; }
const std::string& SEALBackend::to_string() { return BACKEND_STRING; }
const API_VERSION& SEALBackend::api_version() { return _version; }

void SEALBackend::set_log_level(int level) {
  ::aluminum_shark::enable_logging(level > 0);
  ::aluminum_shark::set_log_level(level);
}

std::shared_ptr<Monitor> SEALBackend::enable_ressource_monitor(
    bool enable) const {
  if (enable) {
    if (!SEALMonitor::instance) {
      SEALMonitor::instance = std::make_shared<SEALMonitor>();
    }
    SEALCtxt::count_ops = true;
  } else {
    SEALMonitor::instance = nullptr;
    SEALCtxt::count_ops = false;
  }
  return SEALMonitor::instance;
}

std::shared_ptr<SEALMonitor> SEALMonitor::instance;

std::vector<std::string> SEALMonitor::supported_values{
    "ctxt_ctxt_mulitplication",  //
    "ctxt_ptxt_mulitplication",  //
    "ctxt_ctxt_addition",        //
    "ctxt_ptxt_addition",        //
    "ctxt_rotation"};

// helper. the value_no needs to cooresponds to the index in
// SEALMonitor::supported_values
bool SEALMonitor::get_monitor_value(size_t value_no, double& value) {
  if (value_no >= this->supported_values.size()) {
    return false;
  }
  switch (value_no) {
    case 0:
      value = SEALCtxt::mult_ctxt_count;
      return true;
    case 1:
      value = SEALCtxt::mult_ptxt_count;
      return true;
    case 2:
      value = SEALCtxt::add_ctxt_count;
      return true;
    case 3:
      value = SEALCtxt::add_ptxt_count;
      return true;
    case 4:
      value = SEALCtxt::rot_count;
      return true;
    default:
      return false;
  }
}

bool SEALMonitor::get(const std::string& name, double& value) {
  size_t count = 0;
  for (auto& n : supported_values) {
    if (n == name) {
      return get_monitor_value(count, value);
    }
    ++count;
  }
  return false;
};

bool SEALMonitor::get_next(std::string& name, double& value) {
  name = supported_values[_count];
  get_monitor_value(_count, value);
  _count = ++_count % supported_values.size();
  return _count != 0;
}

const std::vector<std::string>& SEALMonitor::values() {
  return supported_values;
}

}  // namespace aluminum_shark