#ifndef ALUMINUM_SHARK_SEAL_BACKEND_UTILS_H
#define ALUMINUM_SHARK_SEAL_BACKEND_UTILS_H

#include <exception>
#include <string>

#include "backend_logging.h"

namespace aluminum_shark {

// log the internals of a ciphertext and plaintext operations when they mess up
//TODO RP: remove std::cout
template <class T, class U>
void logComputationError(const T& lhs, const U& rhs,
                         const std::string& operation, const std::string& file,
                         int line, const std::exception* e = nullptr) {
  BACKEND_LOG_FAIL_FILE_LINE(file, line)
      << operation
      << " failed reason: " << (e == nullptr ? "none given" : e->what())
      << std::endl;
  BACKEND_LOG_FAIL_FILE_LINE(file, line)
      << "lhs scale: " << lhs.scale() << " rhs scale: " << rhs.scale()
      << std::endl;
  BACKEND_LOG_FAIL_FILE_LINE(file, line) << "lhs parms_id: [ ";
  for (auto i : lhs.parms_id()) {
    std::cout << i << ", ";
  }
  std::cout << "] rhs parms_id: [ ";
  for (auto i : rhs.parms_id()) {
    std::cout << i << ", ";
  }
  std::cout << "]" << std::endl;
}

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_UTILS_H */
