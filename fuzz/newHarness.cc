#include <turbojpeg.h>
#include <stdlib.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 4) return 0;

  tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
  if (!handle) return 0;

  // Enable ICC profile extraction
  tj3Set(handle, TJPARAM_ENABLEICCP, 1);
  tj3Set(handle, TJPARAM_SCANLIMIT, 500);

  // Attempt to parse header
  if (tj3DecompressHeader(handle, data, size) == 0) {
    unsigned char *iccBuf = NULL;
    size_t iccSize = 0;

    // Try to get ICC profile
    if (tj3GetICCProfile(handle, &iccBuf, &iccSize) == 0 && iccBuf && iccSize > 0) {
      // Touch some bytes to keep fuzzer happy
      unsigned char dummy = 0;
      for (size_t i = 0; i < iccSize && i < 8; i++) dummy ^= iccBuf[i];

      // Free the buffer
      tj3Free(iccBuf);
    }
  }

  tj3Destroy(handle);
  return 0;
}
