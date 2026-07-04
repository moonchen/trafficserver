#include "iocore/eventsystem/IOBuffer.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>
#include "../BIO_MIOBuffer.h"

#include <vector>

#include "iocore/eventsystem/EventSystem.h"
#include "tscore/BaseLogFile.h"
#include "tscore/Diags.h"
#include "tscore/Layout.h"
#include "tscore/ink_config.h"

namespace
{
// BoringSSL does not expose the public BIO_{write,read}_ex helpers; for that build
// production registers the classic int-based callbacks (see BIO_MIOBuffer.cc).
// Drive whichever API the build uses so the test exercises the same code path the
// SSL layer does. Gated on the same probe production uses to pick the callbacks.
int
bio_write_compat(BIO *bio, const void *data, size_t len, size_t *written)
{
#if defined(HAVE_BIO_METH_SET_WRITE_EX)
  return BIO_write_ex(bio, data, len, written);
#else
  int n    = BIO_write(bio, data, static_cast<int>(len));
  *written = n > 0 ? static_cast<size_t>(n) : 0;
  return n > 0 ? 1 : 0;
#endif
}

int
bio_read_compat(BIO *bio, void *data, size_t len, size_t *readbytes)
{
#if defined(HAVE_BIO_METH_SET_WRITE_EX)
  return BIO_read_ex(bio, data, len, readbytes);
#else
  int n      = BIO_read(bio, data, static_cast<int>(len));
  *readbytes = n > 0 ? static_cast<size_t>(n) : 0;
  return n > 0 ? 1 : 0;
#endif
}
} // namespace

TEST_CASE("BIO_MIOBuffer create and destroy", "[BIO_MIOBuffer]")
{
  BIO *bio = BIO_new(BIO_s_miobuffer());
  REQUIRE(bio != nullptr);

  int result = BIO_free(bio);
  REQUIRE(result == 1);
}

TEST_CASE("BIO_MIOBuffer set buffer", "[BIO_MIOBuffer]")
{
  BIO *bio = BIO_new(BIO_s_miobuffer());
  REQUIRE(bio != nullptr);

  MIOBuffer *buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);

  REQUIRE(buffer != nullptr);

  int result = miobuffer_set_buffer(bio, buffer, nullptr);
  REQUIRE(result == 1);

  result = BIO_free(bio);
  REQUIRE(result == 1);

  free_MIOBuffer(buffer);
}

TEST_CASE("BIO_MIOBuffer reading and writing", "[BIO_MIOBuffer]")
{
  BIO *bio = BIO_new(BIO_s_miobuffer());
  REQUIRE(bio != nullptr);

  MIOBuffer *buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);
  REQUIRE(buffer != nullptr);

  int result = miobuffer_set_buffer(bio, buffer, buffer->alloc_reader());
  REQUIRE(result == 1);

  const char *data    = "Hello, MIOBuffer!";
  size_t      written = 0;
  result              = bio_write_compat(bio, data, strlen(data), &written);
  REQUIRE(result == 1);
  REQUIRE(written == strlen(data));

  result = BIO_eof(bio);
  REQUIRE(result == 0);

  // Read out all the data
  char   read_buffer[32];
  size_t readbytes = 0;
  result           = bio_read_compat(bio, read_buffer, sizeof(read_buffer), &readbytes);
  REQUIRE(result == 1);
  REQUIRE(readbytes == strlen(data));
  REQUIRE(strncmp(read_buffer, data, readbytes) == 0);
  result = BIO_eof(bio); // MIOBuffer doesn't have EOF
  REQUIRE(result == 0);

  // Should still be able to write after reading
  const char *more_data    = "More data!";
  size_t      more_written = 0;
  result                   = bio_write_compat(bio, more_data, strlen(more_data), &more_written);
  REQUIRE(result == 1);
  REQUIRE(more_written == strlen(more_data));
  result = BIO_flush(bio);
  REQUIRE(result == 1);
  result = BIO_eof(bio);
  REQUIRE(result == 0);
  // Read the new data
  char   read_buffer2[32];
  size_t readbytes2 = 0;
  result            = bio_read_compat(bio, read_buffer2, sizeof(read_buffer2), &readbytes2);
  REQUIRE(result == 1);
  REQUIRE(readbytes2 == strlen(more_data));
  REQUIRE(strncmp(read_buffer2, more_data, readbytes2) == 0);

  result = BIO_free(bio);
  REQUIRE(result == 1);

  free_MIOBuffer(buffer);
}

// Test BIO retry flags are set when buffer is empty
TEST_CASE("BIO_MIOBuffer retry flags", "[BIO_MIOBuffer]")
{
  BIO *bio = BIO_new(BIO_s_miobuffer());
  REQUIRE(bio != nullptr);

  MIOBuffer *buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);
  REQUIRE(buffer != nullptr);

  int result = miobuffer_set_buffer(bio, nullptr, buffer->alloc_reader());
  REQUIRE(result == 1);

  // Set the buffer to empty
  buffer->clear();

  size_t readbytes = 0;
  result           = bio_read_compat(bio, nullptr, 0, &readbytes);
  REQUIRE(result == 0);
  REQUIRE(readbytes == 0);

  result = BIO_free(bio);
  REQUIRE(result == 1);

  free_MIOBuffer(buffer);
}

// The layered SSLNetVConnection write path depends on this BIO never asking the
// SSL layer to retry a write. MIOBuffer::write() grows on demand and always
// absorbs the full record, so BIO_write never short-writes and never raises
// BIO_should_write -- which is why SSL_write can never return WANT_WRITE for us.
// SSLNetVConnection encodes that as a release assert; pin the invariant here so a
// future change that bounds the write BIO trips this test instead of that assert.
TEST_CASE("BIO_MIOBuffer write BIO absorbs multi-block writes without retry", "[BIO_MIOBuffer]")
{
  BIO *bio = BIO_new(BIO_s_miobuffer());
  REQUIRE(bio != nullptr);

  MIOBuffer *buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);
  REQUIRE(buffer != nullptr);

  int result = miobuffer_set_buffer(bio, buffer, nullptr);
  REQUIRE(result == 1);

  // Several 32K blocks worth of data, handed over in a single write call so it
  // must span block boundaries the way a large TLS record flush would.
  std::vector<char> payload(200 * 1024, 'x');
  size_t            written = 0;
  result                    = bio_write_compat(bio, payload.data(), payload.size(), &written);

  REQUIRE(result == 1);                // full success, not a short write
  REQUIRE(written == payload.size());  // every byte absorbed across block boundaries
  REQUIRE(BIO_should_write(bio) == 0); // never asked the SSL layer to retry the write
  REQUIRE(BIO_should_retry(bio) == 0);

  result = BIO_free(bio);
  REQUIRE(result == 1);

  free_MIOBuffer(buffer);
}

// BIO_CTRL_PENDING must report exactly what the read reader can see (the SSL layer relies on
// this to know whether ciphertext is buffered), and BIO_CTRL_FLUSH is always a successful no-op.
TEST_CASE("BIO_MIOBuffer ctrl pending and flush", "[BIO_MIOBuffer]")
{
  BIO *bio = BIO_new(BIO_s_miobuffer());
  REQUIRE(bio != nullptr);

  MIOBuffer *buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);
  REQUIRE(buffer != nullptr);

  int result = miobuffer_set_buffer(bio, buffer, buffer->alloc_reader());
  REQUIRE(result == 1);

  REQUIRE(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nullptr) == 0);
  REQUIRE(BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nullptr) == 1);

  const char *data    = "pending-bytes";
  size_t      written = 0;
  result              = bio_write_compat(bio, data, strlen(data), &written);
  REQUIRE(result == 1);
  REQUIRE(written == strlen(data));

  REQUIRE(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nullptr) == static_cast<long>(strlen(data)));
  REQUIRE(BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nullptr) == 1);

  result = BIO_free(bio);
  REQUIRE(result == 1);

  free_MIOBuffer(buffer);
}

// miobuffer_consume drops bytes from the read side without copying them out (used to discard a
// consumed PROXY protocol header so SSL_read never sees it); a later read must skip them.
TEST_CASE("BIO_MIOBuffer consume drops bytes before read", "[BIO_MIOBuffer]")
{
  BIO *bio = BIO_new(BIO_s_miobuffer());
  REQUIRE(bio != nullptr);

  MIOBuffer *buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);
  REQUIRE(buffer != nullptr);

  int result = miobuffer_set_buffer(bio, buffer, buffer->alloc_reader());
  REQUIRE(result == 1);

  const char *data    = "DROPMEkeepme";
  size_t      written = 0;
  result              = bio_write_compat(bio, data, strlen(data), &written);
  REQUIRE(result == 1);
  REQUIRE(written == strlen(data));

  miobuffer_consume(bio, 6); // drop "DROPME"
  REQUIRE(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nullptr) == static_cast<long>(strlen(data) - 6));

  char   read_buffer[32];
  size_t readbytes = 0;
  result           = bio_read_compat(bio, read_buffer, sizeof(read_buffer), &readbytes);
  REQUIRE(result == 1);
  REQUIRE(readbytes == strlen("keepme"));
  REQUIRE(strncmp(read_buffer, "keepme", readbytes) == 0);

  result = BIO_free(bio);
  REQUIRE(result == 1);

  free_MIOBuffer(buffer);
}

// miobuffer_has_read_avail toggles with buffered data: false when empty, true after a write,
// false again once drained.
TEST_CASE("BIO_MIOBuffer has_read_avail tracks buffered data", "[BIO_MIOBuffer]")
{
  BIO *bio = BIO_new(BIO_s_miobuffer());
  REQUIRE(bio != nullptr);

  MIOBuffer *buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);
  REQUIRE(buffer != nullptr);

  int result = miobuffer_set_buffer(bio, buffer, buffer->alloc_reader());
  REQUIRE(result == 1);

  REQUIRE(miobuffer_has_read_avail(bio) == false);

  const char *data    = "data";
  size_t      written = 0;
  result              = bio_write_compat(bio, data, strlen(data), &written);
  REQUIRE(result == 1);
  REQUIRE(written == strlen(data));
  REQUIRE(miobuffer_has_read_avail(bio) == true);

  char   read_buffer[32];
  size_t readbytes = 0;
  result           = bio_read_compat(bio, read_buffer, sizeof(read_buffer), &readbytes);
  REQUIRE(result == 1);
  REQUIRE(readbytes == strlen(data));
  REQUIRE(miobuffer_has_read_avail(bio) == false);

  result = BIO_free(bio);
  REQUIRE(result == 1);

  free_MIOBuffer(buffer);
}

struct EventProcessorListener : Catch::EventListenerBase {
  using EventListenerBase::EventListenerBase;

  void
  testRunStarting(Catch::TestRunInfo const &testRunInfo) override
  {
    Layout::create();
    RecProcessInit();
    BaseLogFile *base_log_file = new BaseLogFile("stderr");
    DiagsPtr::set(new Diags(std::string_view{testRunInfo.name.data(), testRunInfo.name.size()}, "" /* tags */, "" /* actions */,
                            base_log_file));

    ink_event_system_init(EVENT_SYSTEM_MODULE_PUBLIC_VERSION);
    eventProcessor.start(1, 1048576); // Hardcoded stacksize at 1MB

    EThread *main_thread = new EThread;
    main_thread->set_specific();
  }
};

CATCH_REGISTER_LISTENER(EventProcessorListener)
