#pragma once

#include <sys/types.h>
#include "iocore/aio/AIO.h"
#include "iocore/cache/Store.h"

struct StripeInitInfo {
  off_t recover_pos;
  AIOCallback vol_aio[4];
  char *vol_h_f;

  StripeInitInfo()
  {
    recover_pos = 0;
    vol_h_f     = static_cast<char *>(ats_memalign(ats_pagesize(), 4 * STORE_BLOCK_SIZE));
    memset(vol_h_f, 0, 4 * STORE_BLOCK_SIZE);
  }

  ~StripeInitInfo()
  {
    for (auto &i : vol_aio) {
      i.action = nullptr;
      i.mutex.clear();
    }
    free(vol_h_f);
  }
};
