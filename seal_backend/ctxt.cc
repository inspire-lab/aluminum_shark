#include "ctxt.h"

#include <cxxabi.h>

#include <typeinfo>

#include "ptxt.h"

namespace aluminum_shark {

SEALCtxt::SEALCtxt(const std::string& name, CONTENT_TYPE content_type,
                   const SEALContext& context)
    : SEALCtxt(seal::Ciphertext(), name, content_type, context){};

SEALCtxt::SEALCtxt(seal::Ciphertext ctxt, const std::string& name,
                   CONTENT_TYPE content_type, const SEALContext& context)
    : _name(name),
      _content_type(content_type),
      _context(context),
      _internal_ctxt(ctxt){};

const seal::Ciphertext& SEALCtxt::sealCiphertext() const {
  return _internal_ctxt;
}
seal::Ciphertext& SEALCtxt::sealCiphertext() { return _internal_ctxt; }

CONTENT_TYPE SEALCtxt::content_type() const { return _content_type; }

const std::string& SEALCtxt::name() const { return _name; }

// TODO: more info
const std::string& SEALCtxt::to_string() const { return _name; }

const HEContext* SEALCtxt::getContext() const { return &_context; }

HECtxt* SEALCtxt::deepCopy() {
  SEALCtxt* result = new SEALCtxt(*this);
  return result;
}

// arithmetic operations

// ctxt and ctxt
HECtxt* SEALCtxt::operator+(const HECtxt* other) {
  std::cout << "calling add on " << reinterpret_cast<void*>(this) << " and "
            << reinterpret_cast<const void*>(other) << std::endl;

  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  if (other_ctxt == 0) {
    std::cout << "cast to SEALCtxt failed" << std::endl;
  } else {
    std::cout << "cast to SEALCtxt successful" << std::endl;
  }
  const SEALCtxt* other_ptxt = dynamic_cast<const SEALCtxt*>(other);
  if (other_ptxt == 0) {
    std::cout << "cast to SEALPtxt failed" << std::endl;
  } else {
    std::cout << "cast to SEALPtxt successful" << std::endl;
  }
  std::cout << "casted" << std::endl;
  const HECtxt& ref = *other;
  std::cout << ref.to_string() << std::endl;
  std::cout << _name << std::endl;
  std::cout << other_ctxt->name() << std::endl;
  std::cout << _content_type << std::endl;
  std::cout << _context.to_string() << std::endl;
  SEALCtxt* result =
      new SEALCtxt(_name + " + " + other_ctxt->name(), _content_type, _context);
  std::cout << "created result " << result->to_string() << std::endl;
  _context._evaluator->add(_internal_ctxt, other_ctxt->sealCiphertext(),
                           result->sealCiphertext());
  return result;
}

HECtxt* SEALCtxt::addInPlace(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  _context._evaluator->add_inplace(_internal_ctxt,
                                   other_ctxt->sealCiphertext());
  return this;
}

HECtxt* SEALCtxt::operator*(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  SEALCtxt* result =
      new SEALCtxt(_name + " * " + other_ctxt->name(), _content_type, _context);
  _context._evaluator->multiply(_internal_ctxt, other_ctxt->sealCiphertext(),
                                result->sealCiphertext());
  return result;
}

HECtxt* SEALCtxt::multInPlace(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  _context._evaluator->multiply_inplace(_internal_ctxt,
                                        other_ctxt->sealCiphertext());
  return this;
}

// ctxt and plain

// addition
HECtxt* SEALCtxt::operator+(const HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  std::cout << "calling + on SEALCtxt with " << ptxt->to_string() << std::endl;
  SEALCtxt* result =
      new SEALCtxt(_name + " + plaintext", _content_type, _context);
  std::cout << "Created result Ctxt " << result->to_string() << std::endl;
  std::cout << _internal_ctxt.scale() << std::endl;
  std::cout << ptxt->sealPlaintext().scale() << std::endl;
  SEALPtxt rescaled = ptxt->rescale(_internal_ctxt.scale());
  try {
    _context._evaluator->add_plain(_internal_ctxt, rescaled.sealPlaintext(),
                                   result->sealCiphertext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw e;
  }
  return result;
}

HECtxt* SEALCtxt::addInPlace(const HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  SEALPtxt rescaled = ptxt->rescale(_internal_ctxt.scale());
  _context._evaluator->add_plain_inplace(_internal_ctxt,
                                         rescaled.sealPlaintext());
  return this;
}

HECtxt* SEALCtxt::operator+(long other) {
  SEALCtxt* result = new SEALCtxt(_name + " + " + std::to_string(other),
                                  _content_type, _context);
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->add_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                 result->sealCiphertext());
  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::addInPlace(long other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->add_plain_inplace(_internal_ctxt, ptxt->sealPlaintext());
  delete ptxt;
  return this;
}

HECtxt* SEALCtxt::operator+(double other) {
  SEALCtxt* result = new SEALCtxt(_name + " + " + std::to_string(other),
                                  _content_type, _context);
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->add_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                 result->sealCiphertext());
  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::addInPlace(double other) {
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->add_plain_inplace(_internal_ctxt, ptxt->sealPlaintext());
  delete ptxt;
  return this;
}

// multiplication
HECtxt* SEALCtxt::operator*(const HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  SEALPtxt rescaled = ptxt->rescale(_internal_ctxt.scale());
  SEALCtxt* result =
      new SEALCtxt(_name + " * plaintext", _content_type, _context);
  _context._evaluator->multiply_plain(_internal_ctxt, rescaled.sealPlaintext(),
                                      result->sealCiphertext());
  return result;
}

HECtxt* SEALCtxt::multInPlace(const HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  SEALPtxt rescaled = ptxt->rescale(_internal_ctxt.scale());
  _context._evaluator->multiply_plain_inplace(_internal_ctxt,
                                              rescaled.sealPlaintext());
  return this;
}

HECtxt* SEALCtxt::operator*(long other) {
  SEALCtxt* result = new SEALCtxt(_name + " * " + std::to_string(other),
                                  _content_type, _context);
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->multiply_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                      result->sealCiphertext());
  delete ptxt;
  return result;
}
HECtxt* SEALCtxt::multInPlace(long other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->multiply_plain_inplace(_internal_ctxt,
                                              ptxt->sealPlaintext());
  delete ptxt;
  return this;
}

HECtxt* SEALCtxt::operator*(double other) {
  SEALCtxt* result = new SEALCtxt(_name + " * " + std::to_string(other),
                                  _content_type, _context);
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->multiply_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                      result->sealCiphertext());
  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::multInPlace(double other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->add_plain_inplace(_internal_ctxt, ptxt->sealPlaintext());
  delete ptxt;
  return this;
}

}  // namespace aluminum_shark