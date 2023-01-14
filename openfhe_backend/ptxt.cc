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

// Ptxt and Ptxt
// Addition

HEPtxt* OpenFHEPtxt::operator+(const HEPtxt* other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::addInPlace(const HEPtxt* other) {
  throw std::runtime_error("not implemented");
}

// Subtraction

HEPtxt* OpenFHEPtxt::operator-(const HEPtxt* other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::subInPlace(const HEPtxt* other) {
  throw std::runtime_error("not implemented");
}

// Multiplication

HEPtxt* OpenFHEPtxt::operator*(const HEPtxt* other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::multInPlace(const HEPtxt* other) {
  throw std::runtime_error("not implemented");
}

//  plain and ctxt
// no inplace operations since they need to return a ctxt
// Addition

HECtxt* OpenFHEPtxt::operator+(const HECtxt* other) {
  throw std::runtime_error("not implemented");
}

// Subtraction

HECtxt* OpenFHEPtxt::operator-(const HECtxt* other) {
  throw std::runtime_error("not implemented");
}

// Multiplication

HECtxt* OpenFHEPtxt::operator*(const HECtxt* other) {
  throw std::runtime_error("not implemented");
}

// integral types
// addition

HEPtxt* OpenFHEPtxt::operator+(long other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::addInPlace(long other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::operator+(double other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::addInPlace(double other) {
  throw std::runtime_error("not implemented");
}

// Subtraction

HEPtxt* OpenFHEPtxt::operator-(long other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::subInPlace(long other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::operator-(double other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::subInPlace(double other) {
  throw std::runtime_error("not implemented");
}

// multiplication

HEPtxt* OpenFHEPtxt::operator*(long other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::multInPlace(long other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::operator*(double other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::multInPlace(double other) {
  throw std::runtime_error("not implemented");
}

HEPtxt* OpenFHEPtxt::deepCopy() {
  OpenFHEPtxt* result = new OpenFHEPtxt(*this);
  return result;
}

bool OpenFHEPtxt::isAllZero() const { return _allZero; }

bool OpenFHEPtxt::isAllOne() const { return _allOne; }

}  // namespace aluminum_shark