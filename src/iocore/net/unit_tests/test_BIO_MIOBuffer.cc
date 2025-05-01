#include "iocore/eventsystem/IOBuffer.h"
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "../BIO_MIOBuffer.h"
#include "../../../src/iocore/eventsystem/P_IOBuffer.h"

#include "iocore/eventsystem/EventSystem.h"
#include "tscore/Layout.h"

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

  int result = miobuffer_set_buffer(bio, buffer);
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

  int result = miobuffer_set_buffer(bio, buffer);
  REQUIRE(result == 1);

  const char *data    = "Hello, MIOBuffer!";
  size_t      written = 0;
  result              = BIO_write_ex(bio, data, strlen(data), &written);
  REQUIRE(result == 1);
  REQUIRE(written == strlen(data));

  result = BIO_eof(bio);
  REQUIRE(result == 0);

  // Read out all the data
  char   read_buffer[32];
  size_t readbytes = 0;
  result           = BIO_read_ex(bio, read_buffer, sizeof(read_buffer), &readbytes);
  REQUIRE(result == 1);
  REQUIRE(readbytes == strlen(data));
  REQUIRE(strncmp(read_buffer, data, readbytes) == 0);
  result = BIO_eof(bio); // MIOBuffer doesn't have EOF
  REQUIRE(result == 0);

  // Should still be able to write after reading
  const char *more_data    = "More data!";
  size_t      more_written = 0;
  result                   = BIO_write_ex(bio, more_data, strlen(more_data), &more_written);
  REQUIRE(result == 1);
  REQUIRE(more_written == strlen(more_data));
  result = BIO_flush(bio);
  REQUIRE(result == 1);
  result = BIO_eof(bio);
  REQUIRE(result == 0);
  // Read the new data
  char   read_buffer2[32];
  size_t readbytes2 = 0;
  result            = BIO_read_ex(bio, read_buffer2, sizeof(read_buffer2), &readbytes2);
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

  int result = miobuffer_set_buffer(bio, buffer);
  REQUIRE(result == 1);

  // Set the buffer to empty
  buffer->clear();

  size_t readbytes = 0;
  result           = BIO_read_ex(bio, nullptr, 0, &readbytes);
  REQUIRE(result == 0);
  REQUIRE(readbytes == 0);

  result = BIO_free(bio);
  REQUIRE(result == 1);

  free_MIOBuffer(buffer);
}

struct EventProcessorListener : Catch::TestEventListenerBase {
  using TestEventListenerBase::TestEventListenerBase;

  void
  testRunStarting(Catch::TestRunInfo const &testRunInfo) override
  {
    Layout::create();
    RecProcessInit();
    BaseLogFile *base_log_file = new BaseLogFile("stderr");
    DiagsPtr::set(new Diags(testRunInfo.name, "" /* tags */, "" /* actions */, base_log_file));

    ink_event_system_init(EVENT_SYSTEM_MODULE_PUBLIC_VERSION);
    eventProcessor.start(1, 1048576); // Hardcoded stacksize at 1MB

    EThread *main_thread = new EThread;
    main_thread->set_specific();
  }
};

CATCH_REGISTER_LISTENER(EventProcessorListener);
