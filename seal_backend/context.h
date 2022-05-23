#ifndef ALUMINUM_SHARK_SEAL_BACKEND_CONTEXT_H
#define ALUMINUM_SHARK_SEAL_BACKEND_CONTEXT_H

#include <memory>
#include <string>

#include "backend.h"
#include "he_backend/he_backend.h"

namespace aluminum_shark {

enum CONTENT_TYPE { invalid = -1, LONG, DOUBLE };

template <class T>
CONTENT_TYPE type_to_content_type() {
  return CONTENT_TYPE::invalid;
};

// forward declartion
class SEALPtxt;
class SEALCtxt;

class SEALContext : public HEContext {
 public:
  // Plugin API
  virtual ~SEALContext() {
    std::cout << "Destroying Context " << reinterpret_cast<void*>(this)
              << std::endl;
  };

  virtual const std::string& to_string() const override;

  virtual const HEBackend* getBackend() const override;

  virtual int numberOfSlots() const override;

  // Key management

  // create a public and private key
  virtual void createPublicKey() override;
  virtual void createPrivateKey() override;

  // save public key to file
  virtual void savePublicKey(const std::string& file) override;
  // save private key ot file
  virtual void savePrivateKey(const std::string& file) override;

  // load public key from file
  virtual void loadPublicKey(const std::string& file) override;
  // load private key from file
  virtual void loadPrivateKey(const std::string& file) override;

  // Ciphertext related

  // encryption Functions
  virtual HECtxt* encrypt(std::vector<long>& plain,
                          const std::string name = "") const override;
  virtual HECtxt* encrypt(std::vector<double>& plain,
                          const std::string name = "") const override;
  virtual HECtxt* encrypt(HEPtxt* ptxt,
                          const std::string name = "") const override;

  // decryption functions
  virtual std::vector<long> decryptLong(HECtxt* ctxt) const override;
  virtual std::vector<double> decryptDouble(HECtxt* ctxt) const override;
  // these just forward to decode
  virtual std::vector<long> decryptLong(HEPtxt* ptxt) const override {
    return decodeLong(ptxt);
  }
  virtual std::vector<double> decryptDouble(HEPtxt* ptxt) const override {
    return decodeDouble(ptxt);
  }

  // Plaintext related

  // encoding
  virtual HEPtxt* encode(const std::vector<long>& plain) const override;
  virtual HEPtxt* encode(const std::vector<double>& plain) const override;
  // encoding
  HEPtxt* encode(const std::vector<long>& plain, double scale) const;
  HEPtxt* encode(const std::vector<double>& plain, double scale) const;

  // decoding
  virtual std::vector<long> decodeLong(HEPtxt*) const override;
  virtual std::vector<double> decodeDouble(HEPtxt*) const override;

  // SEAL specific API
  SEALContext(seal::SEALContext context, const SEALBackend& backend,
              double scale = -1);

  template <class T>
  std::vector<T> decode(const SEALPtxt& ptxt) const;

  const seal::Evaluator& evaluator() const;

  const seal::RelinKeys& relinKeys() const;
  const seal::GaloisKeys& galoisKeys() const;

 private:
  friend class SEALPtxt;
  friend class SEALCtxt;
  // SEAL specific API
  const seal::SEALContext _internal_context;
  const SEALBackend& _backend;
  const double _scale;
  std::unique_ptr<seal::BatchEncoder> _batchencoder;
  std::unique_ptr<seal::CKKSEncoder> _ckksencoder;
  seal::KeyGenerator _keygen;
  seal::PublicKey _pub_key;
  seal::SecretKey _sec_key;
  seal::RelinKeys _relin_keys;
  seal::GaloisKeys _gal_keys;
  std::unique_ptr<seal::Encryptor> _encryptor;
  std::unique_ptr<seal::Evaluator> _evaluator;
  std::unique_ptr<seal::Decryptor> _decryptor;
  bool _pub_key_ready = false;
  bool _sec_key_ready = false;
  bool _is_ckks = false;
  bool _is_bfv = false;
  size_t _slot_count;
  std::string _string_representation;

  bool is_ckks() const;
  bool is_bfv() const;
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_CONTEXT_H */
