#include <turbojpeg.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  tjhandle handle = nullptr;
  unsigned char *iccBuf = nullptr;
  size_t iccSize = 0;
  int width, height, jpegSubsamp, jpegColorspace;
  int result = 0;

  // Skip tiny inputs
  if (size < 4) return 0;

  // Create TurboJPEG decompress handle
  handle = tj3Init(TJINIT_DECOMPRESS);
  if (!handle) return 0;

  // Enable ICC profile extraction
  tj3Set(handle, TJPARAM_ENABLEICCP, 1);

  // Feed JPEG input
  if (tj3DecompressHeader(handle, data, size) != 0) {
    tj3Destroy(handle);
    return 0;
  }

  // Try to get ICC profile
  result = tj3GetICCProfile(handle, &iccBuf, &iccSize);

  // Free ICC buffer if allocated
  if (iccBuf) tj3Free(iccBuf);

  tj3Destroy(handle);
  return 0;
}

