#include "backend_logging.h"

namespace {
// read environment variable to see if we should be logging;
bool log_on =
    std::getenv("ALUMINUM_SHARK_BACKEND_LOGGING") == nullptr
        ? false
        : std::stoi(std::getenv("ALUMINUM_SHARK_BACKEND_LOGGING")) == 1;
}  // namespace

namespace aluminum_shark {
namespace seal_backend {
bool log() { return log_on; }

NullStream& nullstream() {
  static NullStream nullstream;
  return nullstream;
}

}  // namespace seal_backend
}  // namespace aluminum_shark