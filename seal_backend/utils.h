#ifndef ALUMINUM_SHARK_SEAL_BACKEND_UTILS_H
#define ALUMINUM_SHARK_SEAL_BACKEND_UTILS_H

#include <exception>
#include <string>

#include "backend_logging.h"
#include "seal/seal.h"

namespace aluminum_shark {

// log the internals of a ciphertext and plaintext operations when they mess up
template <class T, class U>
void logComputationError(const T& lhs, const U& rhs,
                         const std::string& operation, const std::string& file,
                         int line, const std::exception* e = nullptr,
                         const seal::SEALContext* context = nullptr) {
  BACKEND_LOG_FILE_LINE(file, line)
      << operation
      << " failed reason: " << (e == nullptr ? "none given" : e->what())
      << std::endl;
  BACKEND_LOG_FILE_LINE(file, line)
      << "lhs scale: " << lhs.scale() << " rhs scale: " << rhs.scale()
      << std::endl;
  if (context) {
    int bit_count = context->get_context_data(lhs.parms_id())
                        ->total_coeff_modulus_bit_count();
    BACKEND_LOG_FILE_LINE(file, line)
        << "max scale: " << std::pow(2, bit_count) << " (" << bit_count
        << " bit)" << std::endl;
  }
  BACKEND_LOG_FILE_LINE(file, line) << "lhs parms_id: [ ";
  for (auto i : lhs.parms_id()) {
    BACKEND_LOG_A << i << ", ";
  }
  BACKEND_LOG_A << "] rhs parms_id: [ ";
  for (auto i : rhs.parms_id()) {
    BACKEND_LOG_A << i << ", ";
  }
  BACKEND_LOG_A << "]" << std::endl;
}

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_UTILS_H */
