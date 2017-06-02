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
#include "tls_client_config.h"
#include "tls_common.h"
#include "tls_mutators.h"
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

static SECStatus AuthCertificateHook(void* arg, PRFileDesc* fd, PRBool checksig,
                                     PRBool isServer) {
  assert(!isServer);
  auto config = reinterpret_cast<ClientConfig*>(arg);
  return config->FailCertificateAuthentication() ? SECFailure : SECSuccess;
}

static void SetSocketOptions(PRFileDesc* fd,
                             std::unique_ptr<ClientConfig>& config) {
  SECStatus rv = SSL_OptionSet(fd, SSL_NO_CACHE, false);
  assert(rv == SECSuccess);
  rv = SSL_OptionSet(fd, SSL_ENABLE_SESSION_TICKETS, true);
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_ENABLE_EXTENDED_MASTER_SECRET,
                     config->EnableExtendedMasterSecret());
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_REQUIRE_DH_NAMED_GROUPS,
                     config->RequireDhNamedGroups());
  assert(rv == SECSuccess);

  rv = SSL_OptionSet(fd, SSL_ENABLE_FALSE_START, config->EnableFalseStart());
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

// This is only called when we set SSL_ENABLE_FALSE_START=1,
// so we can always just set *canFalseStart=true.
static SECStatus CanFalseStartCallback(PRFileDesc* fd, void* arg,
                                       PRBool* canFalseStart) {
  *canFalseStart = true;
  return SECSuccess;
}

static void SetupCallbacks(PRFileDesc* fd, ClientConfig* config) {
  SECStatus rv = SSL_AuthCertificateHook(fd, AuthCertificateHook, config);
  assert(rv == SECSuccess);

  rv = SSL_SetCanFalseStartCallback(fd, CanFalseStartCallback, nullptr);
  assert(rv == SECSuccess);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
  static std::unique_ptr<NSSDatabase> db(new NSSDatabase());
  assert(db != nullptr);

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

  EnableAllProtocolVersions();
  std::unique_ptr<ClientConfig> config(new ClientConfig(data, len));

  // Clear the cache. We never want to resume as we couldn't reproduce that.
  SSL_ClearSessionCache();

  // Reset the RNG state.
  assert(RNG_RandomUpdate(nullptr, 0) == SECSuccess);

  // Create and import dummy socket.
  std::unique_ptr<DummyPrSocket> socket(new DummyPrSocket(data, len));
  static PRDescIdentity id = PR_GetUniqueIdentity("fuzz-client");
  ScopedPRFileDesc fd(DummyIOLayerMethods::CreateFD(id, socket.get()));
  PRFileDesc* ssl_fd = ImportFD(nullptr, fd.get());
  assert(ssl_fd == fd.get());

  // Probably not too important for clients.
  SSL_SetURL(ssl_fd, "server");

  SetSocketOptions(ssl_fd, config);
  EnableAllCipherSuites(ssl_fd);
  SetupCallbacks(ssl_fd, config.get());

  // TODO
  if (DoHandshake(ssl_fd, false) == SECSuccess) {
    sslSocket* ss = ssl_FindSocket(ssl_fd);
    assert(ss != nullptr);

    sslSessionID* sid =
        ssl_LookupSID(&ss->sec.ci.peer, ss->sec.ci.port, ss->peerID, ss->url);
    if (sid) {
      // fprintf(stderr, " >>> Found new SID\n");
      uint8_t hash[fuzzer::kSHA1NumBytes];
      fuzzer::ComputeSHA1(data, len, hash);
      cache.emplace(fuzzer::Sha1ToString(hash),
                    std::vector<uint8_t>(data, data + len));
      ssl_FreeSID(sid);
    }
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
