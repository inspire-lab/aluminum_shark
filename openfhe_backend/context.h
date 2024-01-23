#ifndef ALUMINUM_SHARK_OPENFHE_BACKEND_CONTEXT_H
#define ALUMINUM_SHARK_OPENFHE_BACKEND_CONTEXT_H

#include <memory>
#include <string>

#include "backend.h"
#include "backend_logging.h"
#include "he_backend/he_backend.h"
#include "object_count.h"

namespace aluminum_shark {

enum class CONTENT_TYPE { invalid = -1, LONG, DOUBLE };

template <class T>
CONTENT_TYPE type_to_content_type() {
  return CONTENT_TYPE::invalid;
};

// forward declartion

class OpenFHEPtxt;
class OpenFHECtxt;

class OpenFHEContext : public HEContext {
 public:
  // Plugin API
  virtual ~OpenFHEContext() {
    BACKEND_LOG << "Destroying Context " << reinterpret_cast<void*>(this)
                << std::endl;
    if (AS_OBJECT_COUNT) {
      std::cout << "object statistics:" << std::endl;
      std::cout << "  ptxt still alive count: " << get_ptxt_count()
                << std::endl;
      std::cout << "  max alive ptxt: " << get_max_ptxt_count() << std::endl;
      std::cout << "  total created ptxt: " << get_ptxt_creations()
                << std::endl;
      std::cout << "  total destroyed ptxt: " << get_ptxt_destructions()
                << std::endl;

      std::cout << "  ctxt still alive count: " << get_ctxt_count()
                << std::endl;
      std::cout << "  max alive ctxt: " << get_max_ctxt_count() << std::endl;
      std::cout << "  total created ctxt: " << get_ctxt_creations()
                << std::endl;
      std::cout << "  total destroyed ctxt: " << get_ctxt_destructions()
                << std::endl;
    }
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
  virtual std::shared_ptr<HECtxt> encrypt(
      std::vector<long>& plain, const std::string name = "") const override;
  virtual std::shared_ptr<HECtxt> encrypt(
      std::vector<double>& plain, const std::string name = "") const override;
  virtual std::shared_ptr<HECtxt> encrypt(
      std::shared_ptr<HEPtxt> ptxt, const std::string name = "") const override;

  // decryption functions
  virtual std::vector<long> decryptLong(
      std::shared_ptr<HECtxt> ctxt) const override;
  virtual std::vector<double> decryptDouble(
      std::shared_ptr<HECtxt> ctxt) const override;
  // these just forward to decode
  virtual std::vector<long> decryptLong(
      std::shared_ptr<HEPtxt> ptxt) const override {
    return decodeLong(ptxt);
  }
  virtual std::vector<double> decryptDouble(
      std::shared_ptr<HEPtxt> ptxt) const override {
    return decodeDouble(ptxt);
  }

  // Plaintext related

  // encoding
  virtual std::shared_ptr<HEPtxt> encode(
      const std::vector<long>& plain) const override;
  virtual std::shared_ptr<HEPtxt> encode(
      const std::vector<double>& plain) const override;

  virtual std::shared_ptr<HEPtxt> createPtxt(
      const std::vector<long>& vect) const;
  virtual std::shared_ptr<HEPtxt> createPtxt(
      const std::vector<double>& vec) const;

  virtual std::shared_ptr<HEPtxt> createPtxt(
      std::vector<double>&& vec) const override {
    std::vector<double> temp = vec;
    return createPtxt(temp);
  };

  // decoding
  virtual std::vector<long> decodeLong(std::shared_ptr<HEPtxt>) const override;
  virtual std::vector<double> decodeDouble(
      std::shared_ptr<HEPtxt>) const override;

  virtual HE_SCHEME scheme() const override;

  virtual void startNewGroup(const std::string& name) const override{
      // ignored in openFHE atm
  };

  // OpenFHE specific API
  OpenFHEContext(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> context,
                 const OpenFHEBackend& backend)
      : _internal_context(context), _backend(backend) {
    lbcrypto::SCHEME scheme = context->getSchemeId();

    _is_ckks = scheme == lbcrypto::SCHEME::CKKSRNS_SCHEME;
    _is_bfv = scheme == lbcrypto::SCHEME::BFVRNS_SCHEME;

    _slot_count = context->GetEncodingParams()->GetBatchSize();

    std::stringstream ss;
    ss << "OpenFHE ";
    if (is_bfv()) {
      ss << "BFV context. ";
    } else if (is_ckks()) {
      ss << "CKKS context. ";
    } else {
      ss << "unknown scheme";
    }
    ss << "Ring dimension " << context->GetRingDimension();
    _string_representation = ss.str();
  };

  void encode(OpenFHEPtxt& ptxt, size_t noiseScaleDeg = 1,
              uint32_t level = 0) const;

  std::shared_ptr<HEPtxt> encode_internal(const std::vector<long>& plain,
                                          size_t noiseScaleDeg = 1,
                                          uint32_t level = 0) const;
  std::shared_ptr<HEPtxt> encode_internal(const std::vector<double>& plain,
                                          size_t noiseScaleDeg = 1,
                                          uint32_t level = 0) const;

 private:
  friend class OpenFHEPtxt;
  friend class OpenFHECtxt;
  // OpenFHE specific API
  const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> _internal_context;
  const OpenFHEBackend& _backend;
  lbcrypto::PublicKey<lbcrypto::DCRTPoly> _pub_key;
  lbcrypto::PrivateKey<lbcrypto::DCRTPoly> _sec_key;
  bool _pub_key_ready = false;
  bool _sec_key_ready = false;
  bool _is_ckks = false;
  bool _is_bfv = false;
  size_t _slot_count;
  std::string _string_representation;

  bool is_ckks() const;
  bool is_bfv() const;

  // checks if all values in a vector are 0 or 1. return std::pair<all_zero,
  // all_one>
  template <class T>
  std::pair<bool, bool> all_zero_or_one(const std::vector<T>& in) const {
    bool all_one = true;
    bool all_zero = true;
    if (in.size() == 1) {
      all_zero = in[0] == 0;
      all_one = in[0] == 1;

    } else {
      for (auto i : in) {
        if (i != 0) {
          all_zero = false;
          break;
        }
      }
      for (auto i : in) {
        if (i != 1) {
          all_one = true;
          break;
        }
      }
    }
    return std::pair<bool, bool>(all_zero, all_one);
  };
};

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_OPENFHE_BACKEND_CONTEXT_H */
