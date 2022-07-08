#include "ptxt.h"

#include "ctxt.h"

namespace aluminum_shark {

// SEALPtxt

SEALPtxt::SEALPtxt(seal::Plaintext ptxt, CONTENT_TYPE content_type,
                   const SEALContext& context)
    : _internal_ptxt(ptxt), _content_type(content_type), _context(context) {
  count_ptxt(1);
}

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
  BACKEND_LOG << "resacling plaintext from "
              << std::log2(_internal_ptxt.scale()) << " to " << scale
              << std::endl;
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

SEALPtxt SEALPtxt::rescale(double scale, seal::parms_id_type params_id) const {
  BACKEND_LOG << "resacling plaintext from " << _internal_ptxt.scale() << " to "
              << scale << std::endl;
  if (_content_type == CONTENT_TYPE::LONG) {
    return SEALPtxt(
        static_cast<SEALPtxt*>(_context.encode(long_values, params_id, scale))
            ->sealPlaintext(),
        _content_type, _context);
  } else {
    return SEALPtxt(
        static_cast<SEALPtxt*>(_context.encode(double_values, params_id, scale))
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
// Addition
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

// Subtraction
HEPtxt* SEALPtxt::operator-(const HEPtxt* other) {
  const SEALPtxt* other_ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (_content_type == CONTENT_TYPE::DOUBLE) {
    std::vector<double> result;
    std::function<double(double, double)> op = [](double one, double two) {
      return one - two;
    };
    operation(*other_ptxt, op, result);
    return _context.encode(result);
  } else if (_content_type == CONTENT_TYPE::LONG) {
    std::vector<long> result;
    std::function<long(long, long)> op = [](long one, long two) {
      return one - two;
    };
    operation(*other_ptxt, op, result);
    return _context.encode(result);
  }
  throw std::runtime_error("invlaid content type in plaintext");
}

HEPtxt* SEALPtxt::subInPlace(const HEPtxt* other) {
  const SEALPtxt* other_ptxt = dynamic_cast<const SEALPtxt*>(other);
  if (_content_type == CONTENT_TYPE::DOUBLE) {
    std::vector<double> result;
    std::function<double(double, double)> op = [](double one, double two) {
      return one - two;
    };
    operation(*other_ptxt, op, result);
    SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
    _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
    delete temp_ptxt;
    return this;
  } else if (_content_type == CONTENT_TYPE::LONG) {
    std::vector<long> result;
    std::function<long(long, long)> op = [](long one, long two) {
      return one - two;
    };
    operation(*other_ptxt, op, result);
    SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
    _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
    delete temp_ptxt;
    return this;
  }
  throw std::runtime_error("invlaid content type in plaintext");
}

// Multiplication
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
// Addition
HECtxt* SEALPtxt::operator+(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  SEALCtxt* result = new SEALCtxt(other_ctxt->name() + " + plaintext",
                                  other_ctxt->content_type(), _context);
  _context._evaluator->add_plain(other_ctxt->sealCiphertext(), sealPlaintext(),
                                 result->sealCiphertext());
  return result;
}

// Subtraction
HECtxt* SEALPtxt::operator-(const HECtxt* other) {
  const SEALCtxt* other_ctxt = dynamic_cast<const SEALCtxt*>(other);
  SEALCtxt* result = new SEALCtxt(other_ctxt->name() + " + plaintext",
                                  other_ctxt->content_type(), _context);
  _context._evaluator->sub_plain(other_ctxt->sealCiphertext(), sealPlaintext(),
                                 result->sealCiphertext());
  return result;
}

// Multiplication
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

// Subtraction
HEPtxt* SEALPtxt::operator-(long other) {
  std::vector<long> result;
  std::function<long(long, long)> op = [](long one, long two) {
    return one - two;
  };
  scalarOperation(other, op, result);
  return _context.encode(result);
}

HEPtxt* SEALPtxt::subInPlace(long other) {
  std::vector<long> result;
  std::function<long(long, long)> op = [](long one, long two) {
    return one - two;
  };
  scalarOperation(other, op, result);
  SEALPtxt* temp_ptxt = (SEALPtxt*)_context.encode(result);
  _internal_ptxt = std::move(temp_ptxt->_internal_ptxt);
  delete temp_ptxt;
  return this;
}

HEPtxt* SEALPtxt::operator-(double other) {
  std::vector<double> result;
  std::function<double(double, double)> op = [](double one, double two) {
    return one - two;
  };
  scalarOperation(other, op, result);
  return _context.encode(result);
}

HEPtxt* SEALPtxt::subInPlace(double other) {
  std::vector<double> result;
  std::function<double(double, double)> op = [](double one, double two) {
    return one - two;
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

bool SEALPtxt::isAllZero() const { return _allZero; }
bool SEALPtxt::isAllOne() const { return _allOne; }

}  // namespace aluminum_shark
