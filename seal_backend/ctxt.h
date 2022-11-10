#ifndef ALUMINUM_SHARK_SEAL_BACKEND_CTXT_H
#define ALUMINUM_SHARK_SEAL_BACKEND_CTXT_H

#include "context.h"
#include "he_backend/he_backend.h"
#include "seal/seal.h"

namespace aluminum_shark {

// HE Ciphertext
class SEALCtxt : public HECtxt {
 public:
  // Plugin API
  virtual ~SEALCtxt(){};

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
  virtual HECtxt* rotate(int steps) override;
  virtual HECtxt* rotInPlace(int steps) override;

  // SEAL specific API
  SEALCtxt(const std::string& name, CONTENT_TYPE content_type,
           const SEALContext& context);
  SEALCtxt(seal::Ciphertext ctxt, const std::string& name,
           CONTENT_TYPE content_type, const SEALContext& context);

  seal::Ciphertext& sealCiphertext();
  const seal::Ciphertext& sealCiphertext() const;
  CONTENT_TYPE content_type() const;

  const std::string& name() const;

 private:
  // SEAL specific API
  friend SEALContext;
  std::string _name;
  CONTENT_TYPE _content_type;
  const SEALContext& _context;
  seal::Ciphertext _internal_ctxt;

  SEALCtxt(const SEALCtxt& other) = default;
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_CTXT_H */
