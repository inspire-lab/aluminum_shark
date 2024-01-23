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

  virtual std::shared_ptr<HECtxt> deepCopy();

  // returns information about the ctxt
  std::string info() override { return ""; };

  // arithmetic operations

  // ctxt and ctxt
  virtual std::shared_ptr<HECtxt> operator+(
      const std::shared_ptr<HECtxt> other) override;
  virtual void addInPlace(const std::shared_ptr<HECtxt> other) override;
  virtual std::shared_ptr<HECtxt> operator-(
      const std::shared_ptr<HECtxt> other) override;
  virtual void subInPlace(const std::shared_ptr<HECtxt> other) override;
  virtual std::shared_ptr<HECtxt> operator*(
      const std::shared_ptr<HECtxt> other) override;
  virtual void multInPlace(const std::shared_ptr<HECtxt> other) override;

  // ctxt and plain

  // addition
  virtual std::shared_ptr<HECtxt> operator+(
      std::shared_ptr<HEPtxt> other) override;
  virtual void addInPlace(std::shared_ptr<HEPtxt> other) override;
  virtual std::shared_ptr<HECtxt> operator+(long other) override;
  virtual void addInPlace(long other) override;
  virtual std::shared_ptr<HECtxt> operator+(double other) override;
  virtual void addInPlace(double other) override;

  // subtraction
  virtual std::shared_ptr<HECtxt> operator-(
      std::shared_ptr<HEPtxt> other) override;
  virtual void subInPlace(std::shared_ptr<HEPtxt> other) override;
  virtual std::shared_ptr<HECtxt> operator-(long other) override;
  virtual void subInPlace(long other) override;
  virtual std::shared_ptr<HECtxt> operator-(double other) override;
  virtual void subInPlace(double other) override;

  // multiplication
  virtual std::shared_ptr<HECtxt> operator*(
      std::shared_ptr<HEPtxt> other) override;
  virtual void multInPlace(std::shared_ptr<HEPtxt> other) override;
  virtual std::shared_ptr<HECtxt> operator*(long other) override;
  virtual void multInPlace(long other) override;
  virtual std::shared_ptr<HECtxt> operator*(double other) override;
  virtual void multInPlace(double other) override;

  // Rotation
  virtual std::shared_ptr<HECtxt> rotate(int steps);

  virtual void rotInPlace(int steps);

  virtual size_t size() override;

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
