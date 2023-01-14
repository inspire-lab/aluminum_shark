#ifndef ALUMINUM_SHARK_OPENFHE_BACKEND_CTXT_H
#define ALUMINUM_SHARK_OPENFHE_BACKEND_CTXT_H

#include "context.h"
#include "he_backend/he_backend.h"
#include "openfhe.h"
#include "ptxt.h"

namespace aluminum_shark {

// HE Ciphertext
class OpenFHECtxt : public HECtxt {
 public:
  // Plugin API
  virtual ~OpenFHECtxt(){};

  virtual std::string to_string() const override;

  virtual const HEContext* getContext() const override;

  virtual HECtxt* deepCopy();

  // arithmetic operations

  // ctxt and ctxt
  virtual HECtxt* operator+(const HECtxt* other) override;
  virtual HECtxt* addInPlace(const HECtxt* other) override;
  virtual HECtxt* operator-(const HECtxt* other) override;
  virtual HECtxt* subInPlace(const HECtxt* other) override;
  virtual HECtxt* operator*(const HECtxt* other) override;
  virtual HECtxt* multInPlace(const HECtxt* other) override;

  // ctxt and plain

  // addition
  virtual HECtxt* operator+(HEPtxt* other) override;
  virtual HECtxt* addInPlace(HEPtxt* other) override;
  virtual HECtxt* operator+(long other) override;
  virtual HECtxt* addInPlace(long other) override;
  virtual HECtxt* operator+(double other) override;
  virtual HECtxt* addInPlace(double other) override;

  // subtraction
  virtual HECtxt* operator-(HEPtxt* other) override;
  virtual HECtxt* subInPlace(HEPtxt* other) override;
  virtual HECtxt* operator-(long other) override;
  virtual HECtxt* subInPlace(long other) override;
  virtual HECtxt* operator-(double other) override;
  virtual HECtxt* subInPlace(double other) override;

  // multiplication
  virtual HECtxt* operator*(HEPtxt* other) override;
  virtual HECtxt* multInPlace(HEPtxt* other) override;
  virtual HECtxt* operator*(long other) override;
  virtual HECtxt* multInPlace(long other) override;
  virtual HECtxt* operator*(double other) override;
  virtual HECtxt* multInPlace(double other) override;

  // Rotation
  virtual HECtxt* rotate(int steps);

  virtual HECtxt* rotInPlace(int steps);

  // OpenFHE specific API
  OpenFHECtxt(const std::string& name, CONTENT_TYPE content_type,
              const OpenFHEContext& context);

  OpenFHECtxt(lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ctxt,
              const std::string& name, CONTENT_TYPE content_type,
              const OpenFHEContext& context);

  void setOpenFHECiphertext(
      const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ctxt);

  lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& openFHECiphertext();
  const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& openFHECiphertext() const;

  CONTENT_TYPE content_type() const;

  const std::string& name() const;

 private:
  // OpenFHE specific API
  friend OpenFHEContext;
  std::string _name;
  CONTENT_TYPE _content_type;
  const OpenFHEContext& _context;
  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> _internal_ctxt;

  OpenFHECtxt(const OpenFHECtxt& other) = default;
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_OPENFHE_BACKEND_CTXT_H */
