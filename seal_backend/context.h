#ifndef ALUMINUM_SHARK_SEAL_BACKEND_CONTEXT_H
#define ALUMINUM_SHARK_SEAL_BACKEND_CONTEXT_H

#include <atomic>
#include <memory>
#include <string>

#include "backend.h"
#include "backend_logging.h"
#include "he_backend/he_backend.h"
#include "object_count.h"

namespace aluminum_shark {

// taken from: SEAL/native/src/seal/util/common.h
template <typename T>
constexpr double epsilon = std::numeric_limits<T>::epsilon();

template <typename T,
          typename = std::enable_if_t<std::is_floating_point<T>::value>>
inline bool are_close(T value1, T value2) noexcept {
  double scale_factor =
      std::max<T>({std::fabs(value1), std::fabs(value2), T{1.0}});
  return std::fabs(value1 - value2) < epsilon<T> * scale_factor;
}

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
  // encoding
  std::shared_ptr<HEPtxt> encode(const std::vector<long>& plain,
                                 double scale) const;
  std::shared_ptr<HEPtxt> encode(const std::vector<double>& plain,
                                 double scale) const;
  std::shared_ptr<HEPtxt> encode(const std::vector<long>& plain,
                                 seal::parms_id_type params_id,
                                 double scale) const;
  std::shared_ptr<HEPtxt> encode(const std::vector<double>& plain,
                                 seal::parms_id_type params_id,
                                 double scale) const;

  virtual std::shared_ptr<HEPtxt> createPtxt(
      const std::vector<long>& vect) const;
  virtual std::shared_ptr<HEPtxt> createPtxt(
      const std::vector<double>& vec) const;

  std::shared_ptr<HEPtxt> createPtxt(std::vector<double>&& vec) const;

  // decoding
  virtual std::vector<long> decodeLong(std::shared_ptr<HEPtxt>) const override;
  virtual std::vector<double> decodeDouble(
      std::shared_ptr<HEPtxt>) const override;

  virtual HE_SCHEME scheme() const override;

  // wehn using seal a new group will create a new memory pool,
  void startNewGroup(const std::string& name) const override;

  // SEAL specific API
  SEALContext(seal::SEALContext context, const SEALBackend& backend,
              double scale = -1, bool galois_keys = true);

  template <class T>
  std::vector<T> decode(const SEALPtxt& ptxt) const;

  void encode(SEALPtxt& ptxt, seal::parms_id_type params_id,
              double scale) const;

  const seal::Evaluator& evaluator() const;
  const seal::SEALContext& context() const;
  const seal::RelinKeys& relinKeys() const;
  const seal::GaloisKeys& galoisKeys() const;

 private:
  friend class SEALPtxt;
  friend class SEALCtxt;
  // SEAL specific API
  const seal::SEALContext _internal_context;
  const SEALBackend& _backend;
  const double _scale;
  bool _gen_galois_keys = true;
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

#endif /* ALUMINUM_SHARK_SEAL_BACKEND_CONTEXT_H */
