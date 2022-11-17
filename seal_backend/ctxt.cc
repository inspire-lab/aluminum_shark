#include "ctxt.h"

#include <cxxabi.h>

#include <typeinfo>

#include "logging.h"
#include "ptxt.h"
#include "utils.h"

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
std::string SEALCtxt::to_string() const {
  std::stringstream ss;
  ss << "SEAL Ctxt: " << _name << "scale " << _internal_ctxt.scale();
  return ss.str();
}

const HEContext* SEALCtxt::getContext() const { return &_context; }

HECtxt* SEALCtxt::deepCopy() {
  SEALCtxt* result = new SEALCtxt(*this);
  return result;
}

// arithmetic operations

// ctxt and ctxt

// Addintion

HECtxt* SEALCtxt::operator+(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  SEALCtxt* result =
      new SEALCtxt(_name + " + " + other_ctxt->name(), _content_type, _context);
  try {
    _context._evaluator->add(_internal_ctxt, other_ctxt->sealCiphertext(),
                             result->sealCiphertext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "operator+(HECtxt*)", __FILE__, __LINE__, &e);
    delete result;
    throw;
  }

  return result;
}

HECtxt* SEALCtxt::addInPlace(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  try {
    BACKEND_LOG << "adding. lhs scale " << std::log2(_internal_ctxt.scale())
                << " rhs scale "
                << std::log2(other_ctxt->sealCiphertext().scale()) << std::endl;
    BACKEND_LOG << "\t lhs params index: "
                << _context._internal_context
                       .get_context_data(_internal_ctxt.parms_id())
                       ->chain_index()
                << " \n\t rhs params index "
                << _context._internal_context
                       .get_context_data(
                           other_ctxt->sealCiphertext().parms_id())
                       ->chain_index()
                << std::endl;
    if (_internal_ctxt.parms_id() != other_ctxt->sealCiphertext().parms_id()) {
      auto context_data_lhs = _context._internal_context.get_context_data(
          _internal_ctxt.parms_id());
      auto context_data_rhs = _context._internal_context.get_context_data(
          other_ctxt->sealCiphertext().parms_id());
      // other has a higher modulus. resacle it down and add
      if (context_data_lhs->chain_index() < context_data_rhs->chain_index()) {
        seal::Ciphertext rescaled_ctxt = other_ctxt->sealCiphertext();
        BACKEND_LOG << "parameters mismatch. rescaling other" << std::endl;
        _context._evaluator->mod_switch_to_inplace(rescaled_ctxt,
                                                   _internal_ctxt.parms_id());
        _context._evaluator->add_inplace(_internal_ctxt, rescaled_ctxt);
        return this;
      }

      double last_prime = static_cast<double>(
          context_data_lhs->parms().coeff_modulus().back().value());

      BACKEND_LOG << "last prime " << last_prime << " ("
                  << std::log2(last_prime) << " bits)" << std::endl;

      // x * s / l = y
      // s = y / x * l
      double temp_scale = other_ctxt->sealCiphertext().scale() /
                          _internal_ctxt.scale() * last_prime;
      BACKEND_LOG << "temp ptxt scale: " << temp_scale << " ("
                  << std::log2(temp_scale) << " bits)" << std::endl;
      {
        seal::Plaintext temp_ptxt;
        _context._ckksencoder->encode(1, _internal_ctxt.parms_id(), temp_scale,
                                      temp_ptxt);
        _context._evaluator->multiply_plain_inplace(_internal_ctxt, temp_ptxt);
      }

      // this has a higher modulus. resacle it down and add
      BACKEND_LOG << "parameters mismatch. rescaling this from "
                  << _internal_ctxt.scale() << std::endl;
      _context._evaluator->rescale_to_next_inplace(_internal_ctxt);
      BACKEND_LOG << "rescaling to " << _internal_ctxt.scale() << std::endl;
      // _context._evaluator->mod_switch_to_inplace(
      //     _internal_ctxt, other_ctxt->sealCiphertext().parms_id());
      BACKEND_LOG << "lhs scale " << _internal_ctxt.scale() << " rhs scale "
                  << other_ctxt->sealCiphertext().scale() << std::endl;
    }
    // _internal_ctxt.scale() = other_ctxt->sealCiphertext().scale();
    _context._evaluator->add_inplace(_internal_ctxt,
                                     other_ctxt->sealCiphertext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "addInplace(HECtxt*)", __FILE__, __LINE__, &e);
    throw;
  }
  return this;
}

// subtraction
HECtxt* SEALCtxt::operator-(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  SEALCtxt* result =
      new SEALCtxt(_name + " * " + other_ctxt->name(), _content_type, _context);
  try {
    _context._evaluator->sub(_internal_ctxt, other_ctxt->sealCiphertext(),
                             result->sealCiphertext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "operator-(HECtxt*)", __FILE__, __LINE__, &e);
    delete result;
    throw;
  }

  return result;
}

HECtxt* SEALCtxt::subInPlace(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  try {
    _context._evaluator->sub_inplace(_internal_ctxt,
                                     other_ctxt->sealCiphertext());

  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "subInPlace(HECtxt*)", __FILE__, __LINE__, &e);
    throw;
  }

  return this;
}

// multiplication

HECtxt* SEALCtxt::operator*(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);

  SEALCtxt* result =
      new SEALCtxt(_name + " * " + other_ctxt->name(), _content_type, _context);
  try {
    _context._evaluator->multiply(_internal_ctxt, other_ctxt->sealCiphertext(),
                                  result->sealCiphertext());
    _context._evaluator->relinearize_inplace(result->sealCiphertext(),
                                             _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(result->sealCiphertext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "operatir*(HECtxt*)", __FILE__, __LINE__, &e);
    delete result;
    throw;
  }
  return result;
}

HECtxt* SEALCtxt::multInPlace(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  try {
    _context._evaluator->multiply_inplace(_internal_ctxt,
                                          other_ctxt->sealCiphertext());
    _context._evaluator->relinearize_inplace(_internal_ctxt,
                                             _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(_internal_ctxt);

  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "multInPlace(HECtxt*)", __FILE__, __LINE__, &e);
    throw;
  }
  return this;
}

// ctxt and plain

// addition
HECtxt* SEALCtxt::operator+(HEPtxt* other) {
  SEALPtxt* ptxt = dynamic_cast<SEALPtxt*>(other);
  SEALCtxt* result =
      new SEALCtxt(_name + " + plaintext", _content_type, _context);
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  try {
    _context._evaluator->add_plain(_internal_ctxt, rescaled.sealPlaintext(),
                                   result->sealCiphertext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "opertator+(HEPtxt*)", __FILE__, __LINE__, &e);
    delete result;
    throw;
  }
  return result;
}

HECtxt* SEALCtxt::addInPlace(HEPtxt* other) {
  SEALPtxt* ptxt = dynamic_cast<SEALPtxt*>(other);
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);

  try {
    _context._evaluator->add_plain_inplace(_internal_ctxt,
                                           rescaled.sealPlaintext());
  } catch (const std::exception& e) {
    double scale_factor = std::max<double>(
        {std::fabs(_internal_ctxt.scale()),
         std::fabs(rescaled.sealPlaintext().scale()), double{1.0}});
    bool are_close =
        std::fabs(_internal_ctxt.scale() - rescaled.sealPlaintext().scale()) <
        epsilon<double> * scale_factor;
    BACKEND_LOG << "scales equal: "
                << std::to_string(_internal_ctxt.scale() ==
                                  rescaled.sealPlaintext().scale())
                << " scale difference: "
                << std::to_string(std::fabs(_internal_ctxt.scale() -
                                            rescaled.sealPlaintext().scale()))
                << " are close: " << are_close << std::endl;
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "addInPlace(HEPtxt*)", __FILE__, __LINE__, &e);
    throw;
  }
  return this;
}

HECtxt* SEALCtxt::operator+(long other) {
  SEALCtxt* result = new SEALCtxt(_name + " + " + std::to_string(other),
                                  _content_type, _context);
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  try {
    _context._evaluator->add_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                   result->sealCiphertext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "opertator+(long)", __FILE__, __LINE__, &e);
    delete ptxt;
    throw;
  }
  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::addInPlace(long other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  try {
    _context._evaluator->add_plain_inplace(_internal_ctxt,
                                           ptxt->sealPlaintext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "addInPlace(long)", __FILE__, __LINE__, &e);
    delete ptxt;
    throw;
  }
  delete ptxt;
  return this;
}

HECtxt* SEALCtxt::operator+(double other) {
  SEALCtxt* result = new SEALCtxt(_name + " + " + std::to_string(other),
                                  _content_type, _context);
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  try {
    _context._evaluator->add_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                   result->sealCiphertext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "operator+(double)", __FILE__, __LINE__, &e);
    delete ptxt;
    throw;
  }
  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::addInPlace(double other) {
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  try {
    _context._evaluator->add_plain_inplace(_internal_ctxt,
                                           ptxt->sealPlaintext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "addInPlace(double)", __FILE__, __LINE__, &e);
    delete ptxt;
    throw;
  }
  delete ptxt;
  return this;
}

// subtraction
HECtxt* SEALCtxt::operator-(HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  SEALCtxt* result =
      new SEALCtxt(_name + " + plaintext", _content_type, _context);
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  try {
    _context._evaluator->sub_plain(_internal_ctxt, rescaled.sealPlaintext(),
                                   result->sealCiphertext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "operator-(HEPtxt*)", __FILE__, __LINE__, &e);
    delete result;
    throw;
  }
  return result;
}

HECtxt* SEALCtxt::subInPlace(HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  SEALPtxt rescaled = ptxt->rescale(_internal_ctxt.scale());
  try {
    _context._evaluator->sub_plain_inplace(_internal_ctxt,
                                           rescaled.sealPlaintext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "subInplace-(HEPtxt*)", __FILE__, __LINE__, &e);
    throw;
  }

  return this;
}

HECtxt* SEALCtxt::operator-(long other) {
  SEALCtxt* result = new SEALCtxt(_name + " + " + std::to_string(other),
                                  _content_type, _context);
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  try {
    _context._evaluator->sub_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                   result->sealCiphertext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "operator-(long)", __FILE__, __LINE__, &e);
    delete ptxt;
    throw;
  }

  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::subInPlace(long other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  try {
    _context._evaluator->sub_plain_inplace(_internal_ctxt,
                                           ptxt->sealPlaintext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "subInPlace(long)", __FILE__, __LINE__, &e);
    delete ptxt;
    throw;
  }

  delete ptxt;
  return this;
}

HECtxt* SEALCtxt::operator-(double other) {
  SEALCtxt* result = new SEALCtxt(_name + " + " + std::to_string(other),
                                  _content_type, _context);
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  try {
    _context._evaluator->sub_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                   result->sealCiphertext());
    /* code */
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "operator-(double)", __FILE__, __LINE__, &e);
    delete ptxt;
    throw;
  }

  delete ptxt;
  return result;
}

HECtxt* SEALCtxt::subInPlace(double other) {
  std::vector<double> vec(_context.numberOfSlots(), other);
  SEALPtxt* ptxt = (SEALPtxt*)_context.encode(vec);
  try {
    _context._evaluator->sub_plain_inplace(_internal_ctxt,
                                           ptxt->sealPlaintext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "subInPlace(double)", __FILE__, __LINE__, &e);
    delete ptxt;
    throw;
  }

  delete ptxt;
  return this;
}

// multiplication
HECtxt* SEALCtxt::operator*(HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (ptxt->isAllZero()) {
    // if we multiplied here the scale would the ciphertext scale * plainscale
    // butt since we specifically rescale the plaintext to be the same scale
    // as the ciphertext we can just square the scale and for rescaling the
    // the plaintext before encryption
    // TODO: be smarter about the scale. we should really look at the scale and
    // what the next scale down would lead to and use that scale during encoding
    BACKEND_LOG << "circumventing transparent ciphertext" << std::endl;
    SEALPtxt temp = ptxt->rescale(
        this->_internal_ctxt.scale() * this->_internal_ctxt.scale(),
        _internal_ctxt.parms_id());
    SEALCtxt* res = static_cast<SEALCtxt*>(_context.encrypt(&temp));
    res->_name = _name + " * plaintext";
    _context._evaluator->relinearize_inplace(res->sealCiphertext(),
                                             _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(res->sealCiphertext());
    return res;
  }
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  // shortcut evalution for special case 0
  SEALCtxt* result =
      new SEALCtxt(_name + " * plaintext", _content_type, _context);
  // TODO: shortcut evalution for special case 1
  try {
    _context._evaluator->multiply_plain(
        _internal_ctxt, rescaled.sealPlaintext(), result->sealCiphertext());
    _context._evaluator->relinearize_inplace(result->sealCiphertext(),
                                             _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(result->sealCiphertext());
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "operator*(HEPtxt*)", __FILE__, __LINE__, &e);
    throw;
  }

  return result;
}

HECtxt* SEALCtxt::multInPlace(HEPtxt* other) {
  const SEALPtxt* ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (ptxt->isAllZero()) {
    // if we multiplied here the scale would the ciphertext scale * plainscale
    // butt since we specifically rescale the plaintext to be the same scale
    // as the ciphertext we can just square the scale and for rescaling the
    // the plaintext before encryption
    // TODO: same as operator*(HEPtxt*). use the proper scale during encoding
    SEALPtxt temp = ptxt->rescale(
        std::log2(this->_internal_ctxt.scale() * this->_internal_ctxt.scale()),
        _internal_ctxt.parms_id());
    SEALCtxt* res = static_cast<SEALCtxt*>(_context.encrypt(&temp));
    res->_name = _name + " * plaintext";
    _internal_ctxt = res->sealCiphertext();
    delete res;
    _context._evaluator->relinearize_inplace(_internal_ctxt,
                                             _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(_internal_ctxt);
    return this;
  }
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  try {
    _context._evaluator->multiply_plain_inplace(_internal_ctxt,
                                                rescaled.sealPlaintext());
    // _context._evaluator->relinearize_inplace(_internal_ctxt,
    //                                          _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(_internal_ctxt);
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "multInPlace(HEPtxt*)", __FILE__, __LINE__, &e,
                        &_context._internal_context);
    throw;
  }

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

// masking. a special kind of multiplication where the right hand side
// contains only 0s and 1s
HECtxt* SEALCtxt::mask(HEPtxt* other) {
  HECtxt* result = this->deepCopy();
  return result->maskInPlace(other);
}

HECtxt* SEALCtxt::maskInPlace(HEPtxt* other) {
  SEALPtxt* ptxt = dynamic_cast<SEALPtxt*>(other);
  // check if the masks only contains 0 and 1
  if (_context._backend.use_safe_masking()) {
    if (!ptxt->isValidMask()) {
      BACKEND_LOG << "plaintext is not a valid mask. falling back to normal "
                     "multiplication"
                  << std::endl;
      return this->multInPlace(other);
    }
  }
  ptxt->rescaleInPalce(1, _internal_ctxt.parms_id());
  _context._evaluator->multiply_plain_inplace(_internal_ctxt,
                                              ptxt->sealPlaintext());
  return this;
}

// Rotation
HECtxt* SEALCtxt::rotInPlace(int steps) {
  _context._evaluator->rotate_vector_inplace(_internal_ctxt, steps,
                                             _context._gal_keys);
  return this;
}

HECtxt* SEALCtxt::rotate(int steps) {
  HECtxt* copy = this->deepCopy();
  return copy->rotInPlace(steps);
}

}  // namespace aluminum_shark