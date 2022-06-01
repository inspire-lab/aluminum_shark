#include "ctxt.h"

#include <cxxabi.h>

#include <typeinfo>

#include "logging.h"
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

// Addintion

HECtxt* SEALCtxt::operator+(const HECtxt* other) {
  BACKEND_LOG << "calling add on " << reinterpret_cast<void*>(this) << " and "
              << reinterpret_cast<const void*>(other) << std::endl;

  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  if (other_ctxt == 0) {
    BACKEND_LOG << "cast to SEALCtxt failed" << std::endl;
  } else {
    BACKEND_LOG << "cast to SEALCtxt successful" << std::endl;
  }
  const SEALCtxt* other_ptxt = dynamic_cast<const SEALCtxt*>(other);
  if (other_ptxt == 0) {
    BACKEND_LOG << "cast to SEALPtxt failed" << std::endl;
  } else {
    BACKEND_LOG << "cast to SEALPtxt successful" << std::endl;
  }
  BACKEND_LOG << "casted" << std::endl;
  const HECtxt& ref = *other;
  BACKEND_LOG << ref.to_string() << std::endl;
  BACKEND_LOG << _name << std::endl;
  BACKEND_LOG << other_ctxt->name() << std::endl;
  BACKEND_LOG << _content_type << std::endl;
  BACKEND_LOG << _context.to_string() << std::endl;
  SEALCtxt* result =
      new SEALCtxt(_name + " + " + other_ctxt->name(), _content_type, _context);
  BACKEND_LOG << "created result " << result->to_string() << std::endl;
  _context._evaluator->add(_internal_ctxt, other_ctxt->sealCiphertext(),
                           result->sealCiphertext());
  return result;
}

HECtxt* SEALCtxt::addInPlace(const HECtxt* other) {
  BACKEND_LOG << "adding plaintext in place" << std::endl;
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  BACKEND_LOG << "this scale " << this->_internal_ctxt.scale()
              << " other scale " << other_ctxt->sealCiphertext().scale()
              << std::endl;
  // BACKEND_LOG << "this params_id " << this->_internal_ctxt.parms_id()
  //            << " other params_id " <<
  //            other_ctxt->sealCiphertext().parms_id()
  //            << std::endl;
  //  SEALCtxt rescaled = rescaleToMatch(*other_ctxt);

  // BACKEND_LOG << "this scale " << this->_internal_ctxt.scale() << " other
  // scale
  //  "
  //            << rescaled.sealCiphertext().scale() << std::endl;
  // BACKEND_LOG << "this params_id " << this->_internal_ctxt.parms_id()
  //            << " other params_id " << rescaled.sealCiphertext().parms_id()
  //            << std::endl;

  _context._evaluator->add_inplace(_internal_ctxt,
                                   other_ctxt->sealCiphertext());
  return this;
}

// subtraction
HECtxt* SEALCtxt::operator-(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  SEALCtxt* result =
      new SEALCtxt(_name + " * " + other_ctxt->name(), _content_type, _context);
  _context._evaluator->sub(_internal_ctxt, other_ctxt->sealCiphertext(),
                           result->sealCiphertext());
  return result;
}

HECtxt* SEALCtxt::subInPlace(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  _context._evaluator->sub_inplace(_internal_ctxt,
                                   other_ctxt->sealCiphertext());
  return this;
}

// multiplication

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
  BACKEND_LOG << "calling + on SEALCtxt with " << ptxt->to_string()
              << std::endl;
  SEALCtxt* result =
      new SEALCtxt(_name + " + plaintext", _content_type, _context);
  BACKEND_LOG << "Created result Ctxt " << result->to_string() << std::endl;
  BACKEND_LOG << _internal_ctxt.scale() << std::endl;
  BACKEND_LOG << ptxt->sealPlaintext().scale() << std::endl;
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  BACKEND_LOG << "rescaled ptxt scalte:" << rescaled.sealPlaintext().scale()
              << std::endl;
  try {
    _context._evaluator->add_plain(_internal_ctxt, rescaled.sealPlaintext(),
                                   result->sealCiphertext());
  } catch (const std::exception& e) {
    BACKEND_LOG << e.what() << std::endl;
    throw e;
  }
  return result;
}

HECtxt* SEALCtxt::addInPlace(const HEPtxt* other) {
  BACKEND_LOG << "adding plaintext in place" << std::endl;
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  BACKEND_LOG << "rescaling plain text" << std::endl;
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  BACKEND_LOG << "rescaled" << std::endl;
  BACKEND_LOG << reinterpret_cast<void*>(_context._evaluator.get())
              << std::endl;
  try {
    _context._evaluator->add_plain_inplace(_internal_ctxt,
                                           rescaled.sealPlaintext());
  } catch (const std::exception& e) {
    BACKEND_LOG << e.what() << '\n';
    throw e;
  }

  BACKEND_LOG << "added" << std::endl;
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

// subtraction
HECtxt* SEALCtxt::operator-(const HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  BACKEND_LOG << "calling + on SEALCtxt with " << ptxt->to_string()
              << std::endl;
  SEALCtxt* result =
      new SEALCtxt(_name + " + plaintext", _content_type, _context);
  BACKEND_LOG << "Created result Ctxt " << result->to_string() << std::endl;
  BACKEND_LOG << _internal_ctxt.scale() << std::endl;
  BACKEND_LOG << ptxt->sealPlaintext().scale() << std::endl;
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  BACKEND_LOG << "rescaled ptxt scalte:" << rescaled.sealPlaintext().scale()
              << std::endl;
  try {
    _context._evaluator->sub_plain(_internal_ctxt, rescaled.sealPlaintext(),
                                   result->sealCiphertext());
  } catch (const std::exception& e) {
    BACKEND_LOG << e.what() << std::endl;
    throw e;
  }
  return result;
}

HECtxt* SEALCtxt::subInPlace(const HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  SEALPtxt rescaled = ptxt->rescale(_internal_ctxt.scale());
  _context._evaluator->sub_plain_inplace(_internal_ctxt,
                                         rescaled.sealPlaintext());
  return this;
}

HECtxt* SEALCtxt::operator-(long other) {
  SEALCtxt* result = new SEALCtxt(_name + " + " + std::to_string(other),
                                  _content_type, _context);
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->sub_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                 result->sealCiphertext());
  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::subInPlace(long other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->sub_plain_inplace(_internal_ctxt, ptxt->sealPlaintext());
  delete ptxt;
  return this;
}

HECtxt* SEALCtxt::operator-(double other) {
  SEALCtxt* result = new SEALCtxt(_name + " + " + std::to_string(other),
                                  _content_type, _context);
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->sub_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                 result->sealCiphertext());
  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::subInPlace(double other) {
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  _context._evaluator->sub_plain_inplace(_internal_ctxt, ptxt->sealPlaintext());
  delete ptxt;
  return this;
}

// multiplication
HECtxt* SEALCtxt::operator*(const HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (ptxt->isAllZero()) {
    // if we multiplied here the scale would the ciphertext scale * plainscale
    // butt since we specifically rescale the plaintext to be the same scale as
    // the ciphertext we can just square the scale and for rescaling the the
    // plaintext before encryption
    SEALPtxt temp = ptxt->rescale(
        std::log2(this->_internal_ctxt.scale() * this->_internal_ctxt.scale()));
    SEALCtxt* res = static_cast<SEALCtxt*>(_context.encrypt(&temp));
    res->_name = _name + " * plaintext";
    return res;
  }
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  // shortcut evalution for special case 0
  SEALCtxt* result =
      new SEALCtxt(_name + " * plaintext", _content_type, _context);
  // TODO: shortcut evalution for special case 1
  _context._evaluator->multiply_plain(_internal_ctxt, rescaled.sealPlaintext(),
                                      result->sealCiphertext());
  return result;
}

HECtxt* SEALCtxt::multInPlace(const HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (ptxt->isAllZero()) {
    // if we multiplied here the scale would the ciphertext scale * plainscale
    // butt since we specifically rescale the plaintext to be the same scale as
    // the ciphertext we can just square the scale and for rescaling the the
    // plaintext before encryption
    SEALPtxt temp = ptxt->rescale(
        std::log2(this->_internal_ctxt.scale() * this->_internal_ctxt.scale()));
    SEALCtxt* res = static_cast<SEALCtxt*>(_context.encrypt(&temp));
    res->_name = _name + " * plaintext";
    _internal_ctxt = res->sealCiphertext();
    delete res;
    return this;
  }
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  _context._evaluator->multiply_plain_inplace(_internal_ctxt,
                                              rescaled.sealPlaintext());
  return this;
}

HECtxt* SEALCtxt::operator*(long other) {
  SEALCtxt* result = new SEALCtxt(_name + " * " + std::to_string(other),
                                  _content_type, _context);
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  result->multInPlace(ptxt);
  delete ptxt;
  return result;
}
HECtxt* SEALCtxt::multInPlace(long other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  multInPlace(ptxt);
  delete ptxt;
  return this;
}

HECtxt* SEALCtxt::operator*(double other) {
  SEALCtxt* result = new SEALCtxt(_name + " * " + std::to_string(other),
                                  _content_type, _context);
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  result->multInPlace(ptxt);
  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::multInPlace(double other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  multInPlace(ptxt);
  delete ptxt;
  return this;
}

//Rotation
HECtxt* SEALCtxt::rotInPlace(int steps) {
  _context._evaluator->rotate_vector_inplace(
            _internal_ctxt, steps, _context._gal_keys);
  return this;            
}

HECtxt* SEALCtxt::rotate(int steps) {
    HECtxt* copy = this->deepCopy();
    return copy->rotInPlace(steps);
}

}  // namespace aluminum_shark