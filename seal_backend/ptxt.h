#ifndef ALUMINUM_SHARK_SEAL_BACKEND_PTXT_H
#define ALUMINUM_SHARK_SEAL_BACKEND_PTXT_H

#include <functional>
#include <mutex>
#include <string>

#include "context.h"
#include "he_backend/he_backend.h"
#include "seal/seal.h"

namespace aluminum_shark {
// TODO: save the plain values in here and only return them encoded when
// neeeded
class SEALPtxt : public HEPtxt {
 public:
  // Plugin API
  virtual ~SEALPtxt() { count_ptxt(-1); };

  virtual std::string to_string() const override;

  virtual const HEContext* getContext() const override;

  virtual std::shared_ptr<HEPtxt> deepCopy();

  // SEAL specific API
  SEALPtxt(seal::Plaintext ptxt, CONTENT_TYPE content_type,
           const SEALContext& context);

  SEALPtxt(SEALPtxt&& other);
  // SEALPtxt& operator=(SEALPtxt&& other);

  seal::Plaintext& sealPlaintext();
  const seal::Plaintext& sealPlaintext() const;

  CONTENT_TYPE content_type() const;

  // rescale the plaintext to 2^scale
  SEALPtxt rescale(double scale) const;
  SEALPtxt rescale(double scale, seal::parms_id_type params_id) const;
  void rescaleInPalce(double scale, seal::parms_id_type params_id);

  SEALPtxt scaleToMatch(const SEALPtxt& ptxt) const;

  SEALPtxt scaleToMatch(const SEALCtxt& ctxt) const;
  void scaleToMatchInPlace(const SEALCtxt& ctxt);

  bool isAllZero() const;
  bool isAllOne() const;

  bool isValidMask() const;

  std::mutex mutex;

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

  SEALPtxt(const SEALPtxt& other)
      : _content_type(other._content_type),
        _context(other._context),
        _allZero(other._allZero),
        _allOne(other._allOne) {
    count_ptxt(1);
  };
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_PTXT_H */