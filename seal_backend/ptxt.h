#ifndef ALUMINUM_SHARK_SEAL_BACKEND_PTXT_H
#define ALUMINUM_SHARK_SEAL_BACKEND_PTXT_H

#include <functional>
#include <string>

#include "context.h"
#include "he_backend/he_backend.h"
#include "seal/seal.h"

namespace aluminum_shark {
// TODO: save the plain values in here and only return them encoded when neeeded
class SEALPtxt : public HEPtxt {
 public:
  // Plugin API
  virtual ~SEALPtxt(){};

  virtual const std::string& to_string() const override;

  virtual const HEContext* getContext() const override;

  // Ptxt and Ptxt
  // Addition
  virtual HEPtxt* operator+(const HEPtxt* other) override;
  virtual HEPtxt* addInPlace(const HEPtxt* other) override;

  // Subtraction
  virtual HEPtxt* operator-(const HEPtxt* other) override;
  virtual HEPtxt* subInPlace(const HEPtxt* other) override;

  // Multiplication

  virtual HEPtxt* operator*(const HEPtxt* other) override;
  virtual HEPtxt* multInPlace(const HEPtxt* other) override;

  //  plain and ctxt
  // no inplace operations since they need to return a ctxt
  virtual HECtxt* operator+(const HECtxt* other) override;
  virtual HECtxt* operator-(const HECtxt* other) override;
  virtual HECtxt* operator*(const HECtxt* other) override;

  // integral types
  // addition
  virtual HEPtxt* operator+(long other) override;
  virtual HEPtxt* addInPlace(long other) override;
  virtual HEPtxt* operator+(double other) override;
  virtual HEPtxt* addInPlace(double other) override;

  // Subtraction
  virtual HEPtxt* operator-(long other) override;
  virtual HEPtxt* subInPlace(long other) override;
  virtual HEPtxt* operator-(double other) override;
  virtual HEPtxt* subInPlace(double other) override;

  // multiplication
  virtual HEPtxt* operator*(long other) override;
  virtual HEPtxt* multInPlace(long other) override;
  virtual HEPtxt* operator*(double other) override;
  virtual HEPtxt* multInPlace(double other) override;

  virtual HEPtxt* deepCopy();

  // SEAL specific API
  SEALPtxt(seal::Plaintext ptxt, CONTENT_TYPE content_type,
           const SEALContext& context);
  seal::Plaintext& sealPlaintext();
  const seal::Plaintext& sealPlaintext() const;

  CONTENT_TYPE content_type() const;

  // rescale the plaintext to 2^scale
  SEALPtxt rescale(double scale) const;
  SEALPtxt rescale(double scale, seal::parms_id_type params_id) const;

  SEALPtxt scaleToMatch(const SEALPtxt& ptxt) const;

  SEALPtxt scaleToMatch(const SEALCtxt& ctxt) const;

  bool isAllZero() const;
  bool isAllOne() const;

 protected:
  seal::Plaintext _internal_ptxt;
  std::vector<long> long_values;
  std::vector<double> double_values;

 private:
  friend SEALContext;
  // SEAL specific API
  CONTENT_TYPE _content_type;
  const SEALContext& _context;
  bool _allZero = false;
  bool _allOne = false;

  SEALPtxt(const SEALPtxt& other) = default;

  // Performs the element wise operation given by `op` of this plain text and
  // the `other` and writes the result into `destination`
  template <class T>
  void operation(const SEALPtxt& other, const std::function<T(T, T)>& op,
                 std::vector<T>& destination) {
    if (_content_type != other.content_type()) {
      throw std::invalid_argument("Plaintexts must have the same encoding");
    }
    std::vector<T> own_content = _context.decode<T>(*this);
    const SEALContext* other_context = (const SEALContext*)(other.getContext());
    std::vector<T> other_content = other_context->decode<T>(other);
    if (own_content.size() != other_content.size()) {
      throw std::invalid_argument("Plaintexts encode different batchsizes");
    }
    destination.reserve(own_content.size());
    for (size_t i = 0; i < own_content.size(); ++i) {
      destination[i] = op(own_content[i], other_content[i]);
    }
  };

  // Performs the element wise operation given by `op` of this plain text and
  // `other` and writes the result into `destination`
  template <class T>
  void scalarOperation(T other, const std::function<T(T, T)>& op,
                       std::vector<T>& destination) {
    if (_content_type != type_to_content_type<T>()) {
      throw std::invalid_argument("Plaintexts must have the same encoding");
    }
    std::vector<T> own_content = _context.decode<T>(*this);
    destination.reserve(own_content.size());
    for (size_t i = 0; i < own_content.size(); ++i) {
      destination[i] = op(own_content[i], other);
    }
  };
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_PTXT_H */
