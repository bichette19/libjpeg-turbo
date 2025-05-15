#include <turbojpeg.h>
#include <stdlib.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  tjhandle handle = NULL;
  unsigned char *iccBuf = NULL;
  int width = 0, height = 0;
  size_t iccSize = 0;

  if ((handle = tj3Init(TJINIT_DECOMPRESS)) == NULL)
    goto bailout;
  
  // Enable ICC profile extraction
  tj3Set(handle, TJPARAM_ENABLEICCP, 1);
  tj3Set(handle, TJPARAM_SCANLIMIT, 500);
  // Attempt to parse header
  tj3DecompressHeader(handle, data, size);
  width = tj3Get(handle, TJPARAM_JPEGWIDTH);
  height = tj3Get(handle, TJPARAM_JPEGHEIGHT);
  
  if (width < 1 || height < 1 || (uint64_t)width * height > 1048576)
    goto bailout;

  // Try to get ICC profile
  if (tj3GetICCProfile(handle, &iccBuf, &iccSize) == 0 && iccBuf && iccSize > 0) {
      // Touch some bytes to keep fuzzer happy
    unsigned char dummy = 0;
    for (size_t i = 0; i < iccSize && i < 8; i++) dummy ^= iccBuf[i];

    tj3Free(iccBuf);
    iccBuf = NULL;
  }
  
  bailout:
    if (iccBuf) tj3Free(iccBuf);  // Double-check if not already freed
    tj3Destroy(handle);
    return 0;
}
