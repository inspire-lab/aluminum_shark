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

  virtual std::shared_ptr<HEPtxt> deepCopy();

  // returns the size of the plaintext in bytes
  virtual size_t size() override;

  // returns information about the ctxt
  std::string info() override { return ""; };

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
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_OPENFHE_BACKEND_PTXT_H */
