#include "ptxt.h"

#include "ctxt.h"

namespace aluminum_shark {

// SEALPtxt

SEALPtxt::SEALPtxt(seal::Plaintext ptxt, CONTENT_TYPE content_type,
                   const SEALContext& context)
    : _internal_ptxt(ptxt), _content_type(content_type), _context(context) {
  count_ptxt(1);
}

SEALPtxt::SEALPtxt(SEALPtxt&& other)
    : _content_type(std::move(other._content_type)),
      _context(other._context),
      _allZero(std::move(other._allZero)),
      _allOne(std::move(other._allOne)) {}

// SEALPtxt& SEALPtxt::operator=(SEALPtxt&& other) {
//   _content_type = std::move(other._content_type);
//   _context = other._context;
//   _allZero = std::move(other._allZero);
//   _allOne = std::move(other._allOne);
// }

seal::Plaintext& SEALPtxt::sealPlaintext() { return _internal_ptxt; }
const seal::Plaintext& SEALPtxt::sealPlaintext() const {
  return _internal_ptxt;
}

CONTENT_TYPE SEALPtxt::content_type() const { return _content_type; }

// TODO: better strings
static const std::string placeholder = "this is a plaintext";
std::string SEALPtxt::to_string() const { return placeholder; }

const HEContext* SEALPtxt::getContext() const { return &_context; }

size_t SEALPtxt::size() {
  seal::Plaintext& ptxt = _internal_ptxt;
  std::shared_ptr<HEPtxt> ptr;
  if (ptxt.coeff_count() == 0) {
    // plaintext is empty
    ptr = _context.encode(double_values);
    ptxt = std::dynamic_pointer_cast<SEALPtxt>(ptr)->sealPlaintext();
  }
  // time to calculate the size
  // size of the coefficient modulus (number of primes) times the degree of the
  // polynomial modulus.
  auto parms =
      _context._internal_context.get_context_data(ptxt.parms_id())->parms();
  std::size_t coeff_modulus_size = parms.coeff_modulus().size();
  std::size_t poly_modulus_degree = parms.poly_modulus_degree();
  return coeff_modulus_size * poly_modulus_degree * 8;
}

SEALPtxt SEALPtxt::rescale(double scale) const {
  BACKEND_LOG << "resacling plaintext from "
              << std::log2(_internal_ptxt.scale()) << " to " << scale
              << std::endl;
  if (_content_type == CONTENT_TYPE::LONG) {
    std::vector<long> content = _context.decode<long>(*this);
    return SEALPtxt(
        std::dynamic_pointer_cast<SEALPtxt>(_context.encode(content, scale))
            ->sealPlaintext(),
        _content_type, _context);
  } else {
    std::vector<double> content = _context.decode<double>(*this);
    return SEALPtxt(
        std::dynamic_pointer_cast<SEALPtxt>(_context.encode(content, scale))
            ->sealPlaintext(),
        _content_type, _context);
  }
}

SEALPtxt SEALPtxt::rescale(double scale, seal::parms_id_type params_id) const {
  BACKEND_LOG << "resacling plaintext from " << _internal_ptxt.scale() << " to "
              << scale << std::endl;
  if (_content_type == CONTENT_TYPE::LONG) {
    return SEALPtxt(std::dynamic_pointer_cast<SEALPtxt>(
                        _context.encode(long_values, params_id, scale))
                        ->sealPlaintext(),
                    _content_type, _context);
  } else {
    return SEALPtxt(std::dynamic_pointer_cast<SEALPtxt>(
                        _context.encode(double_values, params_id, scale))
                        ->sealPlaintext(),
                    _content_type, _context);
  }
}

void SEALPtxt::rescaleInPalce(double scale, seal::parms_id_type params_id) {
  BACKEND_LOG << "resacling plaintext from " << _internal_ptxt.scale() << " to "
              << scale << std::endl;
  _context.encode(*this, params_id, scale);
}

SEALPtxt SEALPtxt::scaleToMatch(const SEALPtxt& ptxt) const {
  return rescale(ptxt.sealPlaintext().scale(), ptxt.sealPlaintext().parms_id());
}

SEALPtxt SEALPtxt::scaleToMatch(const SEALCtxt& ctxt) const {
  return rescale(ctxt.sealCiphertext().scale(),
                 ctxt.sealCiphertext().parms_id());
}

void SEALPtxt::scaleToMatchInPlace(const SEALCtxt& ctxt) {
  rescaleInPalce(ctxt.sealCiphertext().scale(),
                 ctxt.sealCiphertext().parms_id());
}

bool SEALPtxt::isValidMask() const {
  if (_content_type == CONTENT_TYPE::DOUBLE) {
    for (const auto& v : double_values) {
      if (v != 0 || v != 1) {
        return false;
      }
    }
  } else if (_content_type == CONTENT_TYPE::LONG) {
    for (const auto& v : long_values) {
      if (v != 0 || v != 1) {
        return false;
      }
    }
  } else {
    return false;
  }
  return true;
}

std::shared_ptr<HEPtxt> SEALPtxt::deepCopy() {
  SEALPtxt* raw = new SEALPtxt(*this);
  return std::shared_ptr<SEALPtxt>(raw);
}

bool SEALPtxt::isAllZero() const { return _allZero; }
bool SEALPtxt::isAllOne() const { return _allOne; }

}  // namespace aluminum_shark