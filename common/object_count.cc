#include "object_count.h"

#include <algorithm>
#include <mutex>

#include "backend_logging.h"

namespace {
// object counting variables
int ptxt_count_ = 0;
int ctxt_count_ = 0;

int max_ptxt_count_ = 0;
int max_ctxt_count_ = 0;

int ctxt_create_count = 0;
int ctxt_destroy_count = 0;

int ptxt_create_count = 0;
int ptxt_destroy_count = 0;

std::mutex count_mu;
}  // namespace

namespace aluminum_shark {

const bool AS_OBJECT_COUNT = [] {
  bool ret =
      std::getenv("ALUMINUM_SHARK_COUNT_BACKEND_OBJ") == nullptr
          ? false
          : std::stoi(std::getenv("ALUMINUM_SHARK_COUNT_BACKEND_OBJ")) == 1;
  BACKEND_LOG << "using object counting: " << ret << std::endl;
  return ret;
}();

// object counting
void count_ptxt(int count) {
  if (!AS_OBJECT_COUNT) {
    return;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  ptxt_count_ += count;
  max_ptxt_count_ = std::max(max_ptxt_count_, ptxt_count_);
  if (count > 0) {
    ptxt_create_count += count;
  } else {
    ptxt_destroy_count -= count;
  }
  BACKEND_LOG << "ptxt count " << ptxt_count_ << std::endl;
};

void count_ctxt(int count) {
  if (!AS_OBJECT_COUNT) {
    return;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  ctxt_count_ += count;
  max_ctxt_count_ = std::max(max_ctxt_count_, ctxt_count_);
  if (count > 0) {
    ctxt_create_count += count;
    BACKEND_LOG << "ctxt count " << ctxt_count_
                << "ctxt creation no: " << ctxt_create_count << std::endl;
  } else {
    ctxt_destroy_count -= count;
    BACKEND_LOG << "ctxt count " << ctxt_count_
                << "ctxt destroy no: " << ctxt_destroy_count << std::endl;
  }
};

int get_ptxt_count() {
  if (!AS_OBJECT_COUNT) {
    return -1;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  return ptxt_count_;
};

int get_ctxt_count() {
  if (!AS_OBJECT_COUNT) {
    return -1;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  return ctxt_count_;
};

int get_max_ptxt_count() {
  if (!AS_OBJECT_COUNT) {
    return -1;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  return max_ptxt_count_;
}

int get_max_ctxt_count() {
  if (!AS_OBJECT_COUNT) {
    return -1;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  return max_ctxt_count_;
}

int get_ptxt_creations() {
  if (!AS_OBJECT_COUNT) {
    return -1;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  return ptxt_create_count;
}
int get_ptxt_destructions() {
  if (!AS_OBJECT_COUNT) {
    return -1;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  return ptxt_destroy_count;
}

int get_ctxt_creations() {
  if (!AS_OBJECT_COUNT) {
    return -1;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  return ctxt_create_count;
}

int get_ctxt_destructions() {
  if (!AS_OBJECT_COUNT) {
    return -1;
  }
  std::lock_guard<std::mutex> guard(count_mu);
  return ctxt_destroy_count;
}

}  // namespace aluminum_shark