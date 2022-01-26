#include "ptxt.h"

#include "ctxt.h"

namespace aluminum_shark {

// SEALPtxt

SEALPtxt::SEALPtxt(seal::Plaintext ptxt, CONTENT_TYPE content_type,
                   const SEALContext& context)
    : _internal_ptxt(ptxt), _content_type(content_type), _context(context) {}

seal::Plaintext& SEALPtxt::sealPlaintext() { return _internal_ptxt; }
const seal::Plaintext& SEALPtxt::sealPlaintext() const {
  return _internal_ptxt;
}

CONTENT_TYPE SEALPtxt::content_type() const { return _content_type; }

// TODO: better strings
static const std::string placeholder = "this is a plaintext";
const std::string& SEALPtxt::to_string() const { return placeholder; }

const HEContext* SEALPtxt::getContext() const { return &_context; }

SEALPtxt SEALPtxt::rescale(double scale) const {
  if (_content_type == CONTENT_TYPE::LONG) {
    std::vector<long> content = _context.decode<long>(*this);
    return SEALPtxt(static_cast<SEALPtxt*>(_context.encode(content, scale))
                        ->sealPlaintext(),
                    _content_type, _context);
  } else {
    std::vector<double> content = _context.decode<double>(*this);
    return SEALPtxt(static_cast<SEALPtxt*>(_context.encode(content, scale))
                        ->sealPlaintext(),
                    _content_type, _context);
  }
}

// template instantiation
template void SEALPtxt::operation<double>(
    const SEALPtxt& other, const std::function<double(double, double)>& op,
    std::vector<double>& destination);
template void SEALPtxt::operation<long>(
    const SEALPtxt& other, const std::function<long(long, long)>& op,
    std::vector<long>& destination);
template void SEALPtxt::scalarOperation<double>(
    double other, const std::function<double(double, double)>& op,
    std::vector<double>& destination);
template void SEALPtxt::scalarOperation<long>(
    long other, const std::function<long(long, long)>& op,
    std::vector<long>& destination);

// Ptxt and Ptxt
HEPtxt* SEALPtxt::operator+(const HEPtxt* other) {
  const SEALPtxt* other_ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (_content_type == CONTENT_TYPE::DOUBLE) {
    std::vector<double> result;
    std::function<double(double, double)> op = [](double one, double two) {
      return one + two;
    };
    operation(*other_ptxt, op, result);
    return _context.encode(result);
  } else if (_content_type == CONTENT_TYPE::LONG) {
    std::vector<long> result;
    std::function<long(long, long)> op = [](long one, long two) {
      return one + two;
    };
    operation(*other_ptxt, op, result);
    return _context.encode(result);
  }
  throw std::runtime_error("invlaid content type in plaintext");
}

HEPtxt* SEALPtxt::addInPlace(const HEPtxt* other) {
  const SEALPtxt* other_ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (_content_type == CONTENT_TYPE::DOUBLE) {
    std::vector<double> result;
    std::function<double(double, double)> op = [](double one, double two) {
      return one + two;
    };
    operation(*other_ptxt, op, result);
    SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
    _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
    delete temp_ptxt;
    return this;
  } else if (_content_type == CONTENT_TYPE::LONG) {
    std::vector<long> result;
    std::function<long(long, long)> op = [](long one, long two) {
      return one + two;
    };
    operation(*other_ptxt, op, result);
    SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
    _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
    delete temp_ptxt;
    return this;
  }
  throw std::runtime_error("invlaid content type in plaintext");
}

HEPtxt* SEALPtxt::operator*(const HEPtxt* other) {
  const SEALPtxt* other_ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (_content_type == CONTENT_TYPE::DOUBLE) {
    std::vector<double> result;
    std::function<double(double, double)> op = [](double one, double two) {
      return one * two;
    };
    operation(*other_ptxt, op, result);
    return _context.encode(result);
  } else if (_content_type == CONTENT_TYPE::LONG) {
    std::vector<long> result;
    std::function<long(long, long)> op = [](long one, long two) {
      return one * two;
    };
    operation(*other_ptxt, op, result);
    return _context.encode(result);
  }
  throw std::runtime_error("invlaid content type in plaintext");
}

HEPtxt* SEALPtxt::multInPlace(const HEPtxt* other) {
  const SEALPtxt* other_ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (_content_type == CONTENT_TYPE::DOUBLE) {
    std::vector<double> result;
    std::function<double(double, double)> op = [](double one, double two) {
      return one * two;
    };
    operation(*other_ptxt, op, result);
    SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
    _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
    delete temp_ptxt;
    return this;
  } else if (_content_type == CONTENT_TYPE::LONG) {
    std::vector<long> result;
    std::function<long(long, long)> op = [](long one, long two) {
      return one * two;
    };
    operation(*other_ptxt, op, result);
    SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
    _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
    delete temp_ptxt;
    return this;
  }
  throw std::runtime_error("invlaid content type in plaintext");
}

//  plain and ctxt
// no inplace operations since they need to return a ctxt
HECtxt* SEALPtxt::operator+(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  SEALCtxt* result = new SEALCtxt(other_ctxt->name() + " + plaintext",
                                  other_ctxt->content_type(), _context);
  _context._evaluator->add_plain(other_ctxt->sealCiphertext(), sealPlaintext(),
                                 result->sealCiphertext());
  return result;
}

HECtxt* SEALPtxt::operator*(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  SEALCtxt* result = new SEALCtxt(other_ctxt->name() + " + plaintext",
                                  other_ctxt->content_type(), _context);
  _context._evaluator->multiply_plain(
      other_ctxt->sealCiphertext(), sealPlaintext(), result->sealCiphertext());
  return result;
}

// integral types
// addition
HEPtxt* SEALPtxt::operator+(long other) {
  std::vector<long> result;
  std::function<long(long, long)> op = [](long one, long two) {
    return one + two;
  };
  scalarOperation(other, op, result);
  return _context.encode(result);
}

HEPtxt* SEALPtxt::addInPlace(long other) {
  std::vector<long> result;
  std::function<long(long, long)> op = [](long one, long two) {
    return one + two;
  };
  scalarOperation(other, op, result);
  SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
  _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
  delete temp_ptxt;
  return this;
}

HEPtxt* SEALPtxt::operator+(double other) {
  std::vector<double> result;
  std::function<double(double, double)> op = [](double one, double two) {
    return one + two;
  };
  scalarOperation(other, op, result);
  return _context.encode(result);
}

HEPtxt* SEALPtxt::addInPlace(double other) {
  std::vector<double> result;
  std::function<double(double, double)> op = [](double one, double two) {
    return one + two;
  };
  scalarOperation(other, op, result);
  SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
  _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
  delete temp_ptxt;
  return this;
}

// multiplication
HEPtxt* SEALPtxt::operator*(long other) {
  std::vector<long> result;
  std::function<long(long, long)> op = [](long one, long two) {
    return one * two;
  };
  scalarOperation(other, op, result);
  return _context.encode(result);
}

HEPtxt* SEALPtxt::multInPlace(long other) {
  std::vector<long> result;
  std::function<long(long, long)> op = [](long one, long two) {
    return one * two;
  };
  scalarOperation(other, op, result);
  SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
  _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
  delete temp_ptxt;
  return this;
}

HEPtxt* SEALPtxt::operator*(double other) {
  std::vector<double> result;
  std::function<double(double, double)> op = [](double one, double two) {
    return one * two;
  };
  scalarOperation(other, op, result);
  return _context.encode(result);
}

HEPtxt* SEALPtxt::multInPlace(double other) {
  std::vector<double> result;
  std::function<double(double, double)> op = [](double one, double two) {
    return one * two;
  };
  scalarOperation(other, op, result);
  SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
  _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
  delete temp_ptxt;
  return this;
}

HEPtxt* SEALPtxt::deepCopy() {
  SEALPtxt* result = new SEALPtxt(*this);
  return result;
}

}  // namespace aluminum_shark
