#ifndef ALUMINUM_SHARK_SEAL_BACKEND_UTILS_H
#define ALUMINUM_SHARK_SEAL_BACKEND_UTILS_H

#include <exception>
#include <mutex>
#include <sstream>
#include <string>

#include "backend_logging.h"
#include "seal/seal.h"

namespace aluminum_shark {

/// @brief Should not be used outside of utils.h
/// @tparam T
/// @return
template <typename T>
std::mutex& get_mutex() {
  static std::mutex _mutex;
  return _mutex;
}

// log the internals of a ciphertext and plaintext operations when they mess up
// TODO RP: remove std::cout
template <class T, class U>
void logComputationError(const T& lhs, const U& rhs,
                         const std::string& operation, const std::string& file,

                         int line, const std::exception* e = nullptr,
                         const seal::SEALContext* context = nullptr) {
  // when we get here things have failed. We don't want other failuers messing
  // with our analysis. so lock it all down.
  std::lock_guard<std::mutex> lock(get_mutex<void>());

  std::stringstream ss;
  ss << operation
     << " failed reason: " << (e == nullptr ? "none given" : e->what())
     << std::endl;
  ss << "\tlhs scale: " << lhs.scale() << " rhs scale: " << rhs.scale()
     << std::endl;
  if (context) {
    int bit_count = context->get_context_data(lhs.parms_id())
                        ->total_coeff_modulus_bit_count();
    ss << "\tmax scale: " << std::pow(2, bit_count) << " (" << bit_count
       << " bit)" << std::endl;
    ss << "\tchain index: "
       << context->get_context_data(lhs.parms_id())->chain_index() << std::endl;
  }
  ss << "\tlhs parms_id: [ ";

  for (auto i : lhs.parms_id()) {
    ss << i << ", ";
  }
  ss << "] rhs parms_id: [ ";
  for (auto i : rhs.parms_id()) {
    ss << i << ", ";
  }
  ss << "]" << std::endl;

  BACKEND_LOG_FAIL_FILE_LINE(file, line) << ss.str() << std::endl;
}

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_UTILS_H */
