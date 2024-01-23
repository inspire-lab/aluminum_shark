
#include "ctxt.h"

#include <mutex>
#include <ostream>
// #include <streambuf>
#include <sstream>

#include "logging.h"
#include "utils/utils.h"

std::mutex global_op_mutex;

namespace aluminum_shark {

std::string OpenFHECtxt::to_string() const {
  std::stringstream ss;
  ss << "OpenFHE Ctxt: " << _name;
  return ss.str();
}

const HEContext* OpenFHECtxt::getContext() const { return &_context; }

std::shared_ptr<HECtxt> OpenFHECtxt::deepCopy() {
  OpenFHECtxt* raw = new OpenFHECtxt(*this);
  std::shared_ptr<OpenFHECtxt> result(raw);
  result->setOpenFHECiphertext(_internal_ctxt->Clone());
  return result;
}

// arithmetic operations

// ctxt and ctxt
std::shared_ptr<HECtxt> OpenFHECtxt::operator+(
    const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<OpenFHECtxt> other_ctxt =
      std::dynamic_pointer_cast<OpenFHECtxt>(other);
  AS_LOG_DEBUG << "adding ciphertext" << std::endl;
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      other_ctxt->openFHECiphertext()->Clone(),
      _name + " + " + other_ctxt->name(), _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalAdd(
        _internal_ctxt, result->openFHECiphertext());
    AS_LOG_DEBUG << "addition complete" << std::endl;
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

void OpenFHECtxt::addInPlace(const std::shared_ptr<HECtxt> other) {
  // std::lock_guard<std::mutex> guard(global_op_mutex);
  AS_LOG_DEBUG << "adding in place ciphertext" << std::endl;
  const std::shared_ptr<OpenFHECtxt> other_ctxt =
      std::dynamic_pointer_cast<OpenFHECtxt>(other);
  try {
    // cecking if we need to do some modswitching
    auto temp = other_ctxt->openFHECiphertext();
    int level_diff = _internal_ctxt->GetLevel() - temp->GetLevel();
    AS_LOG_DEBUG << "lhs level = " << _internal_ctxt->GetLevel()
                 << " rhs level " << temp->GetLevel() << std::endl;
    if (level_diff != 0) {
      temp = temp->Clone();
    }
    if (level_diff > 0) {
      _context._internal_context->LevelReduceInPlace(_internal_ctxt, nullptr,
                                                     level_diff);
      AS_LOG_DEBUG << "Mod switched lhs by " << level_diff
                   << ". lhs level = " << _internal_ctxt->GetLevel()
                   << " rhs level " << temp->GetLevel() << std::endl;
    } else if (level_diff < 0) {
      _context._internal_context->LevelReduceInPlace(temp, nullptr,
                                                     std::abs(level_diff));
      AS_LOG_DEBUG << "Mod switched rhs by " << level_diff
                   << ". lhs level = " << _internal_ctxt->GetLevel()
                   << " rhs level " << temp->GetLevel() << std::endl;
    }
    _context._internal_context->EvalAddInPlace(_internal_ctxt, temp);
    AS_LOG_DEBUG << "addition in place complete" << std::endl;
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
}

std::shared_ptr<HECtxt> OpenFHECtxt::operator-(
    const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<OpenFHECtxt> other_ctxt =
      std::dynamic_pointer_cast<OpenFHECtxt>(other);
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " * " + other_ctxt->name(), _content_type, _context);
  result->setOpenFHECiphertext(other_ctxt->openFHECiphertext()->Clone());
  try {
    auto ctxt = _context._internal_context->EvalSub(
        _internal_ctxt, result->openFHECiphertext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }

  return result;
}

void OpenFHECtxt::subInPlace(const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<OpenFHECtxt> other_ctxt =
      std::dynamic_pointer_cast<OpenFHECtxt>(other);
  try {
    auto temp = other_ctxt->openFHECiphertext()->Clone();
    _context._internal_context->EvalSubInPlace(_internal_ctxt, temp);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
}

std::shared_ptr<HECtxt> OpenFHECtxt::operator*(
    const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<OpenFHECtxt> other_ctxt =
      std::dynamic_pointer_cast<OpenFHECtxt>(other);
  AS_LOG_DEBUG << "multiplying ciphertext" << std::endl;
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      other_ctxt->openFHECiphertext()->Clone(),
      _name + " * " + other_ctxt->name(), _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalSub(
        _internal_ctxt, result->openFHECiphertext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  AS_LOG_DEBUG << "multiplying ciphertext done" << std::endl;
  return result;
}

void OpenFHECtxt::multInPlace(const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<OpenFHECtxt> other_ctxt =
      std::dynamic_pointer_cast<OpenFHECtxt>(other);
  AS_LOG_DEBUG << "multiplying ciphertext in place" << std::endl;
  try {
    _internal_ctxt = _context._internal_context->EvalMult(
        _internal_ctxt, other_ctxt->openFHECiphertext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  AS_LOG_DEBUG << "multiplying ciphertext in place done" << std::endl;
}

// ctxt and plain

// addition
std::shared_ptr<HECtxt> OpenFHECtxt::operator+(std::shared_ptr<HEPtxt> other) {
  const std::shared_ptr<OpenFHEPtxt> ptxt =
      std::dynamic_pointer_cast<OpenFHEPtxt>(other);
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " + plaintext", _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalAdd(_internal_ctxt,
                                                    ptxt->openFHEPlaintext());
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

void OpenFHECtxt::addInPlace(std::shared_ptr<HEPtxt> other) {
  const std::shared_ptr<OpenFHEPtxt> ptxt =
      std::dynamic_pointer_cast<OpenFHEPtxt>(other);
  try {
    _internal_ctxt = _context._internal_context->EvalAdd(
        _internal_ctxt, ptxt->openFHEPlaintext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
}

std::shared_ptr<HECtxt> OpenFHECtxt::operator+(long other) {
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " + " + std::to_string(other), _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalAdd(_internal_ctxt, other);
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

void OpenFHECtxt::addInPlace(long other) {
  try {
    _context._internal_context->EvalAddInPlace(_internal_ctxt, other);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
}

std::shared_ptr<HECtxt> OpenFHECtxt::operator+(double other) {
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " + " + std::to_string(other), _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalAdd(_internal_ctxt, other);
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

void OpenFHECtxt::addInPlace(double other) {
  try {
    _context._internal_context->EvalAddInPlace(_internal_ctxt, other);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
}

// subtraction
std::shared_ptr<HECtxt> OpenFHECtxt::operator-(std::shared_ptr<HEPtxt> other) {
  const std::shared_ptr<OpenFHEPtxt> ptxt =
      std::dynamic_pointer_cast<OpenFHEPtxt>(other);
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " + plaintext", _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalSub(_internal_ctxt,
                                                    ptxt->openFHEPlaintext());
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

void OpenFHECtxt::subInPlace(std::shared_ptr<HEPtxt> other) {
  const std::shared_ptr<OpenFHEPtxt> ptxt =
      std::dynamic_pointer_cast<OpenFHEPtxt>(other);
  try {
    _internal_ctxt = _context._internal_context->EvalSub(
        _internal_ctxt, ptxt->openFHEPlaintext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
}

std::shared_ptr<HECtxt> OpenFHECtxt::operator-(long other) {
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " + " + std::to_string(other), _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalSub(_internal_ctxt, other);
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

void OpenFHECtxt::subInPlace(long other) {
  try {
    _context._internal_context->EvalSubInPlace(_internal_ctxt, other);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
}

std::shared_ptr<HECtxt> OpenFHECtxt::operator-(double other) {
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " + " + std::to_string(other), _content_type, _context);
  try {
    auto ctxt = _context._internal_context->EvalSub(_internal_ctxt, other);
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
  return result;
}

void OpenFHECtxt::subInPlace(double other) {
  try {
    _context._internal_context->EvalSubInPlace(_internal_ctxt, other);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
}

// multiplication
std::shared_ptr<HECtxt> OpenFHECtxt::operator*(std::shared_ptr<HEPtxt> other) {
  // std::lock_guard<std::mutex> guard(global_op_mutex);
  AS_LOG_INFO << "Ctxt plaintext multiplication" << std::endl;
  const std::shared_ptr<OpenFHEPtxt> ptxt =
      std::dynamic_pointer_cast<OpenFHEPtxt>(other);
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " * plaintext", _content_type, _context);
  // shortcut evalution for special case 0
  if (ptxt->isAllZero()) {
    // TODO
  }
  if (ptxt->isAllOne()) {
    AS_LOG_INFO << "ptxt is all one returning" << std::endl;
    result->setOpenFHECiphertext(_internal_ctxt->Clone());
    return result;
  }

  try {
    AS_LOG_INFO << "Starting multiplication" << std::endl;
    auto ctxt = _context._internal_context->EvalMult(_internal_ctxt,
                                                     ptxt->openFHEPlaintext());
    AS_LOG_INFO << "Done" << std::endl;
    result->setOpenFHECiphertext(ctxt);
  } catch (const std::exception& e) {
    AS_LOG_CRITICAL << e.what() << std::endl;
    throw;
  }

  return result;
}

void OpenFHECtxt::multInPlace(std::shared_ptr<HEPtxt> other) {
  const std::shared_ptr<OpenFHEPtxt> ptxt =
      std::dynamic_pointer_cast<OpenFHEPtxt>(other);
  if (ptxt->isAllZero()) {
    // TODO
  }
  if (ptxt->isAllOne()) {
    return;
  }
  try {
    _internal_ctxt = _context._internal_context->EvalMult(
        _internal_ctxt, ptxt->openFHEPlaintext());
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    throw;
  }
}

std::shared_ptr<HECtxt> OpenFHECtxt::operator*(long other) {
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " * " + std::to_string(other), _content_type, _context);

  auto ctxt = _context._internal_context->EvalMult(_internal_ctxt, other);
  result->setOpenFHECiphertext(ctxt);
  return result;
}

void OpenFHECtxt::multInPlace(long other) {
  _context._internal_context->EvalMultInPlace(_internal_ctxt, other);
}

std::shared_ptr<HECtxt> OpenFHECtxt::operator*(double other) {
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " * " + std::to_string(other), _content_type, _context);
  auto ctxt = _context._internal_context->EvalMult(_internal_ctxt, other);
  result->setOpenFHECiphertext(ctxt);
  return result;
}
void OpenFHECtxt::multInPlace(double other) {
  _context._internal_context->EvalMultInPlace(_internal_ctxt, other);
}

// Rotation
std::shared_ptr<HECtxt> OpenFHECtxt::rotate(int steps) {
  std::shared_ptr<OpenFHECtxt> result = std::make_shared<OpenFHECtxt>(
      _name + " rotated " + std::to_string(steps), _content_type, _context);
  auto rotated = _context._internal_context->EvalRotate(_internal_ctxt, steps);
  result->setOpenFHECiphertext(rotated);
  return result;
}

void OpenFHECtxt::rotInPlace(int steps) {
  _internal_ctxt =
      _context._internal_context->EvalRotate(_internal_ctxt, steps);
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

size_t OpenFHECtxt::size() {  // TODO
  return 0;
}

}  // namespace aluminum_shark