#ifndef ALUMINUM_SHARK_SEAL_BACKEND_CTXT_H
#define ALUMINUM_SHARK_SEAL_BACKEND_CTXT_H

#include <memory>

#include "context.h"
#include "he_backend/he_backend.h"
#include "seal/seal.h"

namespace aluminum_shark {

// HE Ciphertext
class SEALCtxt : public HECtxt {
 public:
  // Plugin API
  virtual ~SEALCtxt() { count_ctxt(-1); };

  virtual std::string to_string() const override;

  virtual const HEContext* getContext() const override;

  virtual std::shared_ptr<HECtxt> deepCopy();

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
  virtual std::shared_ptr<HECtxt> rotate(int steps) override;
  virtual void rotInPlace(int steps) override;

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

  SEALCtxt(const SEALCtxt& other)
      : _name(other._name),
        _content_type(other._content_type),
        _context(other._context),
        _internal_ctxt(other._internal_ctxt) {
    count_ctxt(1);
  };
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_CTXT_H */
