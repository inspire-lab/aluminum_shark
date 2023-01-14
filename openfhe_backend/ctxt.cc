
#include "ctxt.h"

#include "logging.h"
#include "utils/utils.h"

namespace aluminum_shark {

std::string OpenFHECtxt::to_string() const {
  std::stringstream ss;
  ss << "OpenFHE Ctxt: " << _name;
  return ss.str();
}

const HEContext* OpenFHECtxt::getContext() const { return &_context; }

HECtxt* OpenFHECtxt::deepCopy() {
  OpenFHECtxt* result = new OpenFHECtxt(*this);
  result->setOpenFHECiphertext(_internal_ctxt->Clone());
  return result;
}

// arithmetic operations

// ctxt and ctxt
HECtxt* OpenFHECtxt::operator+(const HECtxt* other) {
  const OpenFHECtxt* other_ctxt = dynamic_cast<const OpenFHECtxt*>(other);
  OpenFHECtxt* result = new OpenFHECtxt(
      other_ctxt->openFHECiphertext()->Clone(),
      _name + " + " + other_ctxt->name(), _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalAddMutable(
        _internal_ctxt, result->openFHECiphertext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    delete result;
    throw;
  }
  return result;
}

HECtxt* OpenFHECtxt::addInPlace(const HECtxt* other) {
  const OpenFHECtxt* other_ctxt = dynamic_cast<const OpenFHECtxt*>(other);
  try {
    auto temp = other_ctxt->openFHECiphertext()->Clone();
    _context._internal_context->EvalAddMutableInPlace(_internal_ctxt, temp);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return this;
}

HECtxt* OpenFHECtxt::operator-(const HECtxt* other) {
  const OpenFHECtxt* other_ctxt = dynamic_cast<const OpenFHECtxt*>(other);
  OpenFHECtxt* result = new OpenFHECtxt(_name + " * " + other_ctxt->name(),
                                        _content_type, _context);
  result->setOpenFHECiphertext(other_ctxt->openFHECiphertext()->Clone());
  try {
    auto ctxt = _context._internal_context->EvalSubMutable(
        _internal_ctxt, result->openFHECiphertext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    delete result;
    throw;
  }

  return result;
}

HECtxt* OpenFHECtxt::subInPlace(const HECtxt* other) {
  const OpenFHECtxt* other_ctxt = dynamic_cast<const OpenFHECtxt*>(other);
  try {
    auto temp = other_ctxt->openFHECiphertext()->Clone();
    _context._internal_context->EvalSubMutableInPlace(_internal_ctxt, temp);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return this;
}

HECtxt* OpenFHECtxt::operator*(const HECtxt* other) {
  const OpenFHECtxt* other_ctxt = dynamic_cast<const OpenFHECtxt*>(other);

  OpenFHECtxt* result = new OpenFHECtxt(
      other_ctxt->openFHECiphertext()->Clone(),
      _name + " * " + other_ctxt->name(), _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalSubMutable(
        _internal_ctxt, result->openFHECiphertext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    delete result;
    throw;
  }
  return result;
}

HECtxt* OpenFHECtxt::multInPlace(const HECtxt* other) {
  const OpenFHECtxt* other_ctxt = dynamic_cast<const OpenFHECtxt*>(other);
  try {
    auto temp = other_ctxt->openFHECiphertext()->Clone();
    _context._internal_context->EvalMultMutableInPlace(_internal_ctxt, temp);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return this;
}

// ctxt and plain

// addition
HECtxt* OpenFHECtxt::operator+(HEPtxt* other) {
  OpenFHEPtxt* ptxt = dynamic_cast<OpenFHEPtxt*>(other);
  OpenFHECtxt* result =
      new OpenFHECtxt(_name + " + plaintext", _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalAddMutable(
        _internal_ctxt, ptxt->openFHEPlaintext());
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    delete result;
    throw;
  }
  return result;
}

HECtxt* OpenFHECtxt::addInPlace(HEPtxt* other) {
  OpenFHEPtxt* ptxt = dynamic_cast<OpenFHEPtxt*>(other);
  try {
    _internal_ctxt = _context._internal_context->EvalAddMutable(
        _internal_ctxt, ptxt->openFHEPlaintext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return this;
}

HECtxt* OpenFHECtxt::operator+(long other) {
  OpenFHECtxt* result = new OpenFHECtxt(_name + " + " + std::to_string(other),
                                        _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalAdd(_internal_ctxt, other);
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    delete result;
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

HECtxt* OpenFHECtxt::addInPlace(long other) {
  try {
    _context._internal_context->EvalAddInPlace(_internal_ctxt, other);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }

  return this;
}

HECtxt* OpenFHECtxt::operator+(double other) {
  OpenFHECtxt* result = new OpenFHECtxt(_name + " + " + std::to_string(other),
                                        _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalAdd(_internal_ctxt, other);
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    delete result;
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

HECtxt* OpenFHECtxt::addInPlace(double other) {
  try {
    _context._internal_context->EvalAddInPlace(_internal_ctxt, other);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return this;
}

// subtraction
HECtxt* OpenFHECtxt::operator-(HEPtxt* other) {
  const OpenFHEPtxt* ptxt = dynamic_cast<const OpenFHEPtxt*>(other);
  OpenFHECtxt* result =
      new OpenFHECtxt(_name + " + plaintext", _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalSubMutable(
        _internal_ctxt, ptxt->openFHEPlaintext());
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    delete result;
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

HECtxt* OpenFHECtxt::subInPlace(HEPtxt* other) {
  const OpenFHEPtxt* ptxt = dynamic_cast<const OpenFHEPtxt*>(other);
  try {
    _internal_ctxt = _context._internal_context->EvalSubMutable(
        _internal_ctxt, ptxt->openFHEPlaintext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return this;
}

HECtxt* OpenFHECtxt::operator-(long other) {
  OpenFHECtxt* result = new OpenFHECtxt(_name + " + " + std::to_string(other),
                                        _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalSub(_internal_ctxt, other);
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    delete result;
    throw;
  }
  return result;
}

HECtxt* OpenFHECtxt::subInPlace(long other) {
  try {
    _context._internal_context->EvalSubInPlace(_internal_ctxt, other);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return this;
}

HECtxt* OpenFHECtxt::operator-(double other) {
  OpenFHECtxt* result = new OpenFHECtxt(_name + " + " + std::to_string(other),
                                        _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalSub(_internal_ctxt, other);
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    delete result;
    throw;
  }
  return result;
}

HECtxt* OpenFHECtxt::subInPlace(double other) {
  try {
    _context._internal_context->EvalSubInPlace(_internal_ctxt, other);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return this;
}

// multiplication
HECtxt* OpenFHECtxt::operator*(HEPtxt* other) {
  AS_LOG_INFO << "Ctxt plaintext multiplication" << std::endl;
  const OpenFHEPtxt* ptxt = dynamic_cast<const OpenFHEPtxt*>(other);
  OpenFHECtxt* result =
      new OpenFHECtxt(_name + " * plaintext", _content_type, _context);
  // shortcut evalution for special case 0
  if (ptxt->isAllZero()) {
    // TODO
  }
  if (ptxt->isAllOne()) {
    result->setOpenFHECiphertext(_internal_ctxt->Clone());
    return result;
  }

  try {
    auto ctxt = _context._internal_context->EvalMultMutable(
        _internal_ctxt, ptxt->openFHEPlaintext());
    AS_LOG_INFO << "Done" << std::endl;
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    delete result;
    throw;
  }

  return result;
}

HECtxt* OpenFHECtxt::multInPlace(HEPtxt* other) {
  const OpenFHEPtxt* ptxt = dynamic_cast<const OpenFHEPtxt*>(other);
  if (ptxt->isAllZero()) {
    // TODO
  }
  if (ptxt->isAllOne()) {
    return this;
  }
  try {
    _internal_ctxt = _context._internal_context->EvalMultMutable(
        _internal_ctxt, ptxt->openFHEPlaintext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return this;
}

HECtxt* OpenFHECtxt::operator*(long other) {
  OpenFHECtxt* result = new OpenFHECtxt(_name + " * " + std::to_string(other),
                                        _content_type, _context);

  auto ctxt = _context._internal_context->EvalMult(_internal_ctxt, other);
  result->setOpenFHECiphertext(ctxt);
  return result;
}

HECtxt* OpenFHECtxt::multInPlace(long other) {
  _context._internal_context->EvalMultInPlace(_internal_ctxt, other);
  return this;
}

HECtxt* OpenFHECtxt::operator*(double other) {
  OpenFHECtxt* result = new OpenFHECtxt(_name + " * " + std::to_string(other),
                                        _content_type, _context);
  auto ctxt = _context._internal_context->EvalMult(_internal_ctxt, other);
  result->setOpenFHECiphertext(ctxt);
  return result;
}

HECtxt* OpenFHECtxt::multInPlace(double other) {
  _context._internal_context->EvalMultInPlace(_internal_ctxt, other);
  return this;
}

// Rotation
HECtxt* OpenFHECtxt::rotate(int steps) {
  OpenFHECtxt* result = new OpenFHECtxt(
      _name + " rotated " + std::to_string(steps), _content_type, _context);
  auto rotated = _context._internal_context->EvalRotate(_internal_ctxt, steps);
  result->setOpenFHECiphertext(rotated);
  return result;
}

HECtxt* OpenFHECtxt::rotInPlace(int steps) {
  _internal_ctxt =
      _context._internal_context->EvalRotate(_internal_ctxt, steps);
  return this;
}

// OpenFHE specific API
OpenFHECtxt::OpenFHECtxt(const std::string& name, CONTENT_TYPE content_type,
                         const OpenFHEContext& context)
    : OpenFHECtxt(lbcrypto::Ciphertext<lbcrypto::DCRTPoly>(), name,
                  content_type, context) {}

OpenFHECtxt::OpenFHECtxt(lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ctxt,
                         const std::string& name, CONTENT_TYPE content_type,
                         const OpenFHEContext& context)
    : _name(name),
      _content_type(content_type),
      _context(context),
      _internal_ctxt(ctxt) {}

void OpenFHECtxt::setOpenFHECiphertext(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ctxt) {
  _internal_ctxt = ctxt;
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& OpenFHECtxt::openFHECiphertext() {
  return _internal_ctxt;
}

const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& OpenFHECtxt::openFHECiphertext()
    const {
  return _internal_ctxt;
}

CONTENT_TYPE OpenFHECtxt::content_type() const { return _content_type; }

const std::string& OpenFHECtxt::name() const { return _name; }

}  // namespace aluminum_shark