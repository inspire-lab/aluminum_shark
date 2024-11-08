#ifndef ALUMINUM_SHARK_SEAL_BACKEND_LOGGING_H
#define ALUMINUM_SHARK_SEAL_BACKEND_LOGGING_H

#include <iostream>
#include <string>

namespace aluminum_shark {
namespace seal_backend {

class NullStream : public std::ostream {
 public:
  NullStream() : std::ostream(nullptr) {}
  NullStream(const NullStream&) : std::ostream(nullptr) {}
};

template <class T>
const NullStream& operator<<(NullStream&& os, const T& value) {
  return os;
}

NullStream& nullstream();

bool log();

}  // namespace seal_backend
}  // namespace aluminum_shark

// streaming interface
#define BACKEND_LOG_FAIL_FILE_LINE(FILE, LINE) \
  std::cout << "SEAL Backend: [" << FILE << ":" << LINE << "] "
// set FILE and LINE manually
#define BACKEND_LOG_FILE_LINE(FILE, LINE)              \
  (::aluminum_shark::seal_backend::log()               \
       ? std::cout                                     \
       : ::aluminum_shark::seal_backend::nullstream()) \
      << "Backend: [" << FILE << ":" << LINE << "] "

#define BACKEND_LOG BACKEND_LOG_FILE_LINE(__FILE__, __LINE__)

// append to stream
#define BACKEND_LOG_A                    \
  (::aluminum_shark::seal_backend::log() \
       ? std::cout                       \
       : ::aluminum_shark::seal_backend::nullstream())

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_LOGGING_H */