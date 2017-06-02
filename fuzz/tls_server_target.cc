/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>
#include <stdint.h>
#include <map>
#include <memory>

#include "blapi.h"
#include "prinit.h"
#include "ssl.h"
#include "sslimpl.h"

#include "shared.h"
#include "tls_common.h"
#include "tls_mutators.h"
#include "tls_server_certs.h"
#include "tls_server_config.h"
#include "tls_socket.h"

#include "FuzzerSHA1.h"

const uint8_t MAGIC[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0x12};

static std::map<std::string, std::vector<uint8_t>> cache;

/*#ifdef IS_DTLS
__attribute__((constructor)) static void set_is_dtls() {
  TlsMutators::SetIsDTLS();
}
#endif*/

PRFileDesc* ImportFD(PRFileDesc* model, PRFileDesc* fd) {
  /*#ifdef IS_DTLS
    return DTLS_ImportFD(model, fd);
  #else*/
  return SSL_ImportFD(model, fd);
  //#endif
}

class SSLServerSessionCache {
 public:
  SSLServerSessionCache() {
    assert(SSL_ConfigServerSessionIDCache(1024, 0, 0, ".") == SECSuccess);
  }

  ~SSLServerSessionCache() {
    assert(SSL_ShutdownServerSessionIDCache() == SECSuccess);
  }
};

static void SetSocketOptions(PRFileDesc* fd,
                             std::unique_ptr<ServerConfig>& config) {
  SECStatus rv = SSL_OptionSet(fd, SSL_NO_CACHE, false);
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_ENABLE_SESSION_TICKETS, true);
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_REUSE_SERVER_ECDHE_KEY, false);
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_ENABLE_EXTENDED_MASTER_SECRET,
                     config->EnableExtendedMasterSecret());
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_REQUEST_CERTIFICATE, config->RequestCertificate());
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_REQUIRE_CERTIFICATE, config->RequireCertificate());
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_ENABLE_DEFLATE, config->EnableDeflate());
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_CBC_RANDOM_IV, config->EnableCbcRandomIv());
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_REQUIRE_SAFE_NEGOTIATION,
                     config->RequireSafeNegotiation());
  assert(rv == SECSuccess);

  //#ifndef IS_DTLS
  rv =
      SSL_OptionSet(fd, SSL_ENABLE_RENEGOTIATION, SSL_RENEGOTIATE_UNRESTRICTED);
  assert(rv == SECSuccess);
  //#endif
}

static PRStatus InitModelSocket(void* arg) {
  PRFileDesc* fd = reinterpret_cast<PRFileDesc*>(arg);

  EnableAllProtocolVersions();
  EnableAllCipherSuites(fd);
  InstallServerCertificates(fd);

  return PR_SUCCESS;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
  static std::unique_ptr<NSSDatabase> db(new NSSDatabase());
  assert(db != nullptr);

  static std::unique_ptr<SSLServerSessionCache> sessionCache(
      new SSLServerSessionCache());
  assert(sessionCache != nullptr);

  // TODO
  if (len > sizeof(MAGIC) && memcmp(data, MAGIC, sizeof(MAGIC)) == 0) {
    const uint16_t* length =
        reinterpret_cast<const uint16_t*>(&data[sizeof(MAGIC)]);

    if (sizeof(MAGIC) + sizeof(*length) + *length >= len) {
      // fprintf(stderr, " >>> REJECT record with length=%u\n", *length);
      return 0;
    }

    // fprintf(stderr, " >>> Replaying a record with length=%u\n", *length);
    LLVMFuzzerTestOneInput(data + sizeof(MAGIC) + sizeof(*length), *length);
    data += sizeof(MAGIC) + sizeof(*length) + *length;
    len -= sizeof(MAGIC) + sizeof(*length) + *length;
  }

  std::unique_ptr<ServerConfig> config(new ServerConfig(data, len));

  // Clear the cache. We never want to resume as we couldn't reproduce that.
  SSL_ClearSessionCache();

  // Reset the RNG state.
  assert(RNG_RandomUpdate(nullptr, 0) == SECSuccess);

  // Create model socket.
  static ScopedPRFileDesc model(ImportFD(nullptr, PR_NewTCPSocket()));
  assert(model);

  // Initialize the model socket once.
  static PRCallOnceType initModelOnce;
  PR_CallOnceWithArg(&initModelOnce, InitModelSocket, model.get());

  // Create and import dummy socket.
  std::unique_ptr<DummyPrSocket> socket(new DummyPrSocket(data, len));
  static PRDescIdentity id = PR_GetUniqueIdentity("fuzz-server");
  ScopedPRFileDesc fd(DummyIOLayerMethods::CreateFD(id, socket.get()));
  PRFileDesc* ssl_fd = ImportFD(model.get(), fd.get());
  assert(ssl_fd == fd.get());

  SetSocketOptions(ssl_fd, config);

  // TODO
  if (DoHandshake(ssl_fd, true) == SECSuccess) {
    sslSocket* ss = ssl_FindSocket(ssl_fd);
    assert(ss != nullptr);

    uint8_t hash[fuzzer::kSHA1NumBytes];
    fuzzer::ComputeSHA1(data, len, hash);
    cache.emplace(fuzzer::Sha1ToString(hash),
                  std::vector<uint8_t>(data, data + len));
  }

  return 0;
}

// TODO
size_t PrependRecord(uint8_t* data, size_t size, size_t max_size,
                     unsigned int seed) {
  std::mt19937 rng(seed);
  uint16_t len;

  // Pick a record the prepend at random.
  std::uniform_int_distribution<size_t> dist(0, cache.size() - 1);
  auto item = cache.begin();
  std::advance(item, dist(rng));
  auto& rec = item->second;

  if (size + rec.size() + sizeof(MAGIC) + sizeof(len) > max_size) {
    return 0;
  }

  len = rec.size();

  // Make space.
  memmove(data + rec.size() + sizeof(MAGIC) + sizeof(len), data, size);

  // Prepend the magic value.
  memcpy(data, MAGIC, sizeof(MAGIC));

  // Prepend the length.
  memcpy(data + sizeof(MAGIC), &len, sizeof(len));

  // Prepend the record we picked.
  memcpy(data + sizeof(MAGIC) + sizeof(len), rec.data(), rec.size());

  // Return the new size.
  // fprintf(stderr, " >>> Made a new record... of length=%u\n", len);
  return size + rec.size() + sizeof(MAGIC) + sizeof(len);
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
  using namespace TlsMutators;
  return CustomMutate({DropRecord, ShuffleRecords, DuplicateRecord,
                       TruncateRecord, FragmentRecord, PrependRecord},
                      data, size, max_size, seed);
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* data1, size_t size1,
                                            const uint8_t* data2, size_t size2,
                                            uint8_t* out, size_t max_out_size,
                                            unsigned int seed) {
  return TlsMutators::CrossOver(data1, size1, data2, size2, out, max_out_size,
                                seed);
}
