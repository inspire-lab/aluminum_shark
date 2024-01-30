#ifndef HE_API_HE_BACKEND_H
#define HE_API_HE_BACKEND_H
#ifndef ALUMINUM_SHARK_DEPENDENCIES_TENSORFLOW_TENSORFLOW_COMPILER_PLUGIN_ALUMINUM_SHARK_HE_BACKEND_HE_BACKEND_H
#define ALUMINUM_SHARK_DEPENDENCIES_TENSORFLOW_TENSORFLOW_COMPILER_PLUGIN_ALUMINUM_SHARK_HE_BACKEND_HE_BACKEND_H

#include <memory>
#include <string>
#include <vector>

// semantic versioning , increment the:

// MAJOR version when you make incompatible API changes
// MINOR version when you add functionality in a backward compatible manner
// PATCH version when you make backward compatible bug fixes

#define ALUMINUM_SHARK_API_VERSION_MAJOR 0
#define ALUMINUM_SHARK_API_VERSION_MINOR 0
#define ALUMINUM_SHARK_API_VERSION_PATCH 1

// convert macros to string literals
#define AS_STR_HELPER(x) #x
#define AS_STR(x) AS_STR_HELPER(x)
// create version string
#define ALUMINUM_SHARK_API_VERSION_STRING                  \
  AS_STR(ALUMINUM_SHARK_API_VERSION_MAJOR)                 \
  "." AS_STR(ALUMINUM_SHARK_API_VERSION_MINOR) "." AS_STR( \
      ALUMINUM_SHARK_API_VERSION_PATCH)

extern "C" {
// struct to transport data between python and c++.  We can use it recreate
// arbitary named arguments from python in c++. Mainly used to create
// HEContexts. The backend implementation is responsible for sorting out the
// data and what the arguments mean.
struct aluminum_shark_Argument {
  const char* name;
  // 0: int
  // 1: double
  // 2: string
  uint type;

  // if true the `array_` member will point to an array containing `size_`
  // elements of `type`.
  bool is_array = false;

  // data holding variables
  long int_;
  double double_;
  const char* string_;
  // holds data if `is_array` == ture.
  void* array_ = nullptr;
  size_t size_;
};
}  // extern "C"

namespace aluminum_shark {

struct API_VERSION {
  const size_t major = ALUMINUM_SHARK_API_VERSION_MAJOR;
  const size_t minor = ALUMINUM_SHARK_API_VERSION_MINOR;
  const size_t patch = ALUMINUM_SHARK_API_VERSION_PATCH;
  const std::string str = ALUMINUM_SHARK_API_VERSION_STRING;
};

enum HE_SCHEME { CKKS };

class HEContext;
class HECtxt;
class HEPtxt;
class Monitor;

// This class wraps around an externally implemented HE backend. The backend is
// implmented in its own shared library which is loaded dynamically. The backend
// needs to have a function that with the following signature
// `std::shared_ptr<aluminum_shark::HEBackend> createBackend()`
class HEBackend {
 public:
  // Create an HEContect
  virtual ~HEBackend(){};

  virtual std::shared_ptr<HEContext>* createContext(
      std::vector<aluminum_shark_Argument> arguments) = 0;

  virtual const std::string& name() = 0;
  virtual const std::string& to_string() = 0;
  virtual const API_VERSION& api_version() = 0;

  virtual void set_log_level(int level) = 0;

  // enables or disables the moniotr. can return nullptr. enabling an already
  // enabled moitor reutrns the same pointer and does not create a new one
  virtual std::shared_ptr<Monitor> enable_ressource_monitor(bool) const = 0;
  virtual std::shared_ptr<Monitor> get_ressource_monitor() const = 0;

 private:
  std::shared_ptr<void> lib_handle_;
  friend std::shared_ptr<HEBackend> loadBackend(const std::string& lib_path);
};

// Provides all the nessecary functions to create keys, ciphertexts, etc.
class HEContext {
 public:
  virtual ~HEContext(){};

  virtual const std::string& to_string() const = 0;

  virtual const HEBackend* getBackend() const = 0;

  virtual int numberOfSlots() const = 0;

  // Key management

  // create a public and private key
  virtual void createPublicKey() = 0;
  virtual void createPrivateKey() = 0;

  // save public key to file
  virtual void savePublicKey(const std::string& file) = 0;
  // save private key ot file
  virtual void savePrivateKey(const std::string& file) = 0;

  // load public key from file
  virtual void loadPublicKey(const std::string& file) = 0;
  // load private key from file
  virtual void loadPrivateKey(const std::string& file) = 0;

  // Ciphertext related

  // encryption Functions
  virtual std::shared_ptr<HECtxt> encrypt(
      std::vector<long>& plain, const std::string name = "") const = 0;
  virtual std::shared_ptr<HECtxt> encrypt(
      long plain, const std::string name = "") const = 0;
  virtual std::shared_ptr<HECtxt> encrypt(
      std::vector<double>& plain, const std::string name = "") const = 0;
  virtual std::shared_ptr<HECtxt> encrypt(
      double plain, const std::string name = "") const = 0;
  virtual std::shared_ptr<HECtxt> encrypt(
      std::shared_ptr<HEPtxt> ptxt, const std::string name = "") const = 0;

  // decryption functions
  virtual std::vector<long> decryptLong(std::shared_ptr<HECtxt> ctxt) const = 0;
  virtual std::vector<double> decryptDouble(
      std::shared_ptr<HECtxt> ctxt) const = 0;

  // Plaintext related
  // encoding
  virtual std::shared_ptr<HEPtxt> encode(
      const std::vector<long>& plain) const = 0;
  virtual std::shared_ptr<HEPtxt> encode(
      const std::vector<double>& plain) const = 0;

  // creates plaintext objects that need to be encoded on demand
  virtual std::shared_ptr<HEPtxt> createPtxt(
      const std::vector<long>& vec) const = 0;
  virtual std::shared_ptr<HEPtxt> createPtxt(
      const std::vector<double>& vec) const = 0;

  virtual std::shared_ptr<HEPtxt> createPtxt(std::vector<long>&& vec) const = 0;
  virtual std::shared_ptr<HEPtxt> createPtxt(
      std::vector<double>&& vec) const = 0;

  virtual HE_SCHEME scheme() const = 0;

  // other
  // Signals to the backend that ciphertexts that are created next logically
  // belong together. Can be used for optimization by the backend.
  // Starting a new group will close the current group
  virtual void startNewGroup(const std::string& name) const = 0;

 private:
  friend HEBackend;
};

// HE plaintext
class HEPtxt {
 public:
  virtual ~HEPtxt(){};

  virtual std::string to_string() const = 0;

  virtual const HEContext* getContext() const = 0;

  virtual std::shared_ptr<HEPtxt> deepCopy() = 0;

  // returns the size of the plaintext in bytes
  virtual size_t size() = 0;

  // returns information about the ptxt
  virtual std::string info() = 0;

 private:
  friend HEContext;
};

// HE Ciphertext
class HECtxt {
 public:
  virtual ~HECtxt(){};

  virtual std::string to_string() const = 0;

  virtual const HEContext* getContext() const = 0;

  virtual std::shared_ptr<HECtxt> deepCopy() = 0;

  // returns information about the ctxt
  virtual std::string info() = 0;

  // arithmetic operations

  // ctxt and ctxt
  virtual std::shared_ptr<HECtxt> add(const std::shared_ptr<HECtxt> other) = 0;
  virtual void addInPlace(const std::shared_ptr<HECtxt> other) = 0;

  virtual std::shared_ptr<HECtxt> sub(const std::shared_ptr<HECtxt> other) = 0;
  virtual void subInPlace(const std::shared_ptr<HECtxt> other) = 0;

  virtual std::shared_ptr<HECtxt> mult(const std::shared_ptr<HECtxt> other) = 0;
  virtual void multInPlace(const std::shared_ptr<HECtxt> other) = 0;

  // returns the size of the ciphertext in bytes
  virtual size_t size() = 0;

  // ctxt and plain

  // addition
  virtual std::shared_ptr<HECtxt> addInPlace(std::shared_ptr<HEPtxt> other) = 0;
  virtual void add(std::shared_ptr<HEPtxt> other) = 0;
  virtual std::shared_ptr<HECtxt> addInPlace(long other) = 0;
  virtual void add(long other) = 0;
  virtual std::shared_ptr<HECtxt> addInPlace(double other) = 0;
  virtual void add(double other) = 0;

  // subtraction
  virtual std::shared_ptr<HECtxt> sub(std::shared_ptr<HEPtxt> other) = 0;
  virtual void subInPlace(std::shared_ptr<HEPtxt> other) = 0;
  virtual std::shared_ptr<HECtxt> sub(long other) = 0;
  virtual void subInPlace(long other) = 0;
  virtual std::shared_ptr<HECtxt> sub(double other) = 0;
  virtual void subInPlace(double other) = 0;

  // multiplication
  virtual std::shared_ptr<HECtxt> mult(std::shared_ptr<HEPtxt> other) = 0;
  virtual void multInPlace(std::shared_ptr<HEPtxt> other) = 0;
  virtual std::shared_ptr<HECtxt> mult(long other) = 0;
  virtual void multInPlace(long other) = 0;
  virtual std::shared_ptr<HECtxt> mult(double other) = 0;
  virtual void multInPlace(double other) = 0;

  // Rotate
  virtual std::shared_ptr<HECtxt> rotate(int steps) = 0;
  virtual void rotInPlace(int steps) = 0;

 private:
  friend HEContext;
};

// A class to monitor the ressource consumption of the backend.
class Monitor {
 public:
  // retrieves the value specified by name and writes it into value, returns
  // false if the value is not logged or unsoproted;
  virtual bool get(const std::string& name, double& value) = 0;

  // can be used to iterate over all logged valued by this monitor. puts the
  // name of the value into `name` and the value into `value`. Returns false if
  // there are no more values. Calling it again after that restarts
  virtual bool get_next(std::string& name, double& value) = 0;

  // returns a list of all values supported by this monitor
  virtual const std::vector<std::string>& values() = 0;
};

std::shared_ptr<HEBackend> loadBackend(const std::string& lib_path);

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_DEPENDENCIES_TENSORFLOW_TENSORFLOW_COMPILER_PLUGIN_ALUMINUM_SHARK_HE_BACKEND_HE_BACKEND_H \
        */

#endif /* HE_API_HE_BACKEND_H */
