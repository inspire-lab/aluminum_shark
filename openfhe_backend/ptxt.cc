#include "ptxt.h"

namespace aluminum_shark {

OpenFHEPtxt::OpenFHEPtxt(lbcrypto::Plaintext ptxt, CONTENT_TYPE content_type,
                         const OpenFHEContext& context)
    : _internal_ptxt(ptxt), _content_type(content_type), _context(context) {
  count_ptxt(1);
}

lbcrypto::Plaintext& OpenFHEPtxt::openFHEPlaintext() { return _internal_ptxt; }

const lbcrypto::Plaintext& OpenFHEPtxt::openFHEPlaintext() const {
  return _internal_ptxt;
}

CONTENT_TYPE OpenFHEPtxt::content_type() const { return _content_type; }

// TODO: better strings

std::string OpenFHEPtxt::to_string() const { return "this is a plaintext"; }

const HEContext* OpenFHEPtxt::getContext() const { return &_context; }

std::shared_ptr<HEPtxt> OpenFHEPtxt::deepCopy() {
  OpenFHEPtxt* raw = new OpenFHEPtxt(*this);
  // std::shared_ptr<OpenFHEPtxt> result = std::make_shared<OpenFHEPtxt>(*this);
  return std::shared_ptr<OpenFHEPtxt>(raw);
}

size_t OpenFHEPtxt::size() {
  // TODO:
  return 0;
}

bool OpenFHEPtxt::isAllZero() const { return _allZero; }

bool OpenFHEPtxt::isAllOne() const { return _allOne; }

}  // namespace aluminum_shark