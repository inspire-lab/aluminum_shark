#ifndef ALUMINUM_SHARK_OPENFHE_BACKEND_PTXT_H
#define ALUMINUM_SHARK_OPENFHE_BACKEND_PTXT_H

#include <functional>
#include <mutex>
#include <string>

#include "context.h"
#include "he_backend/he_backend.h"
#include "openfhe.h"

namespace aluminum_shark {
// TODO: save the plain values in here and only return them encoded when
// neeeded

class OpenFHEPtxt : public HEPtxt {
 public:
  // Plugin API
  virtual ~OpenFHEPtxt() { count_ptxt(-1); };

  virtual std::string to_string() const override;

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

  // openfhe specific API
  OpenFHEPtxt(lbcrypto::Plaintext ptxt, CONTENT_TYPE content_type,
              const OpenFHEContext& context);
  lbcrypto::Plaintext& openFHEPlaintext();
  const lbcrypto::Plaintext& openFHEPlaintext() const;

  CONTENT_TYPE content_type() const;

  bool isAllZero() const;
  bool isAllOne() const;

  std::mutex mutex;

 protected:
  lbcrypto::Plaintext _internal_ptxt;
  std::vector<long> long_values;
  std::vector<double> double_values;

 private:
  friend OpenFHEContext;
  // SEAL specific API
  CONTENT_TYPE _content_type;
  const OpenFHEContext& _context;
  bool _allZero = false;
  bool _allOne = false;

  OpenFHEPtxt(const OpenFHEPtxt& other)
      : _content_type(other._content_type),
        _context(other._context),
        _allZero(other._allZero),
        _allOne(other._allOne) {
    count_ptxt(1);
  };

  // // Performs the element wise operation given by `op` of this plain text and
  // // the `other` and writes the result into `destination`
  // template <class T>
  // void operation(const SEALPtxt& other, const std::function<T(T, T)>& op,
  //                std::vector<T>& destination) {
  //   if (_content_type != other.content_type()) {
  //     throw std::invalid_argument("Plaintexts must have the same encoding");
  //   }
  //   std::vector<T> own_content = _context.decode<T>(*this);
  //   const SEALContext* other_context = (const
  //   SEALContext*)(other.getContext()); std::vector<T> other_content =
  //   other_context->decode<T>(other); if (own_content.size() !=
  //   other_content.size()) {
  //     throw std::invalid_argument("Plaintexts encode different batchsizes");
  //   }
  //   destination.reserve(own_content.size());
  //   for (size_t i = 0; i < own_content.size(); ++i) {
  //     destination[i] = op(own_content[i], other_content[i]);
  //   }
  // };

  // // Performs the element wise operation given by `op` of this plain text and
  // // `other` and writes the result into `destination`
  // template <class T>
  // void scalarOperation(T other, const std::function<T(T, T)>& op,
  //                      std::vector<T>& destination) {
  //   if (_content_type != type_to_content_type<T>()) {
  //     throw std::invalid_argument("Plaintexts must have the same encoding");
  //   }
  //   std::vector<T> own_content = _context.decode<T>(*this);
  //   destination.reserve(own_content.size());
  //   for (size_t i = 0; i < own_content.size(); ++i) {
  //     destination[i] = op(own_content[i], other);
  //   }
  // };
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_OPENFHE_BACKEND_PTXT_H */