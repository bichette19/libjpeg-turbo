#include <turbojpeg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int myCustomFilter(short *coeff_array, tjregion arrayRegion,
                   tjregion planeRegion, int componentIndex,
                   int transformIndex, tjtransform *transform) {
  // Trivial mutation for fuzzing
  if (coeff_array) coeff_array[0] ^= 1;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  tjhandle handle = NULL;
  unsigned char *dstBufs[1] = { NULL };
  size_t dstSizes[1] = { 0 }, maxBufSize, i;
  int width = 0, height = 0, jpegSubsamp, dstSubsamp;
  tjtransform transforms[1];

  if ((handle = tj3Init(TJINIT_TRANSFORM)) == NULL)
    goto bailout;

  tj3DecompressHeader(handle, data, size);
  width = tj3Get(handle, TJPARAM_JPEGWIDTH);
  height = tj3Get(handle, TJPARAM_JPEGHEIGHT);
  jpegSubsamp = tj3Get(handle, TJPARAM_SUBSAMP);
  tj3Set(handle, TJPARAM_ARITHMETIC, 0);
  tj3Set(handle, TJPARAM_PROGRESSIVE, 0);
  tj3Set(handle, TJPARAM_OPTIMIZE, 0);

  if (width < 1 || height < 1 || (uint64_t)width * height > 1048576)
    goto bailout;

  tj3Set(handle, TJPARAM_SCANLIMIT, 500);
  if (jpegSubsamp < 0 || jpegSubsamp >= TJ_NUMSAMP)
    jpegSubsamp = TJSAMP_444;

  memset(&transforms[0], 0, sizeof(tjtransform));
  transforms[0].customFilter = myCustomFilter;  

  // -------- First transform (none, progressive) --------
  transforms[0].op = TJXOP_NONE;
  transforms[0].options = TJXOPT_PROGRESSIVE | TJXOPT_COPYNONE;
  dstBufs[0] = (unsigned char *)tj3Alloc(tj3JPEGBufSize(width, height, jpegSubsamp));
  if (!dstBufs[0]) goto bailout;

  maxBufSize = tj3JPEGBufSize(width, height, jpegSubsamp);
  tj3Set(handle, TJPARAM_NOREALLOC, 1);

  if (tj3Transform(handle, data, size, 1, dstBufs, dstSizes, transforms) == 0) {
    size_t sum = 0;
    for (i = 0; i < dstSizes[0]; i++) sum += dstBufs[0][i];
    if (sum > 255 * maxBufSize) goto bailout;
  }

  free(dstBufs[0]); dstBufs[0] = NULL;

  // -------- Second transform (transpose + crop + gray) --------
  transforms[0].r.w = (height + 1) / 2;
  transforms[0].r.h = (width + 1) / 2;
  transforms[0].op = TJXOP_TRANSPOSE;
  transforms[0].options = TJXOPT_GRAY | TJXOPT_CROP | TJXOPT_COPYNONE | TJXOPT_OPTIMIZE;
  dstBufs[0] = (unsigned char *)tj3Alloc(tj3JPEGBufSize((height + 1) / 2, (width + 1) / 2, TJSAMP_GRAY));
  if (!dstBufs[0]) goto bailout;

  maxBufSize = tj3JPEGBufSize((height + 1) / 2, (width + 1) / 2, TJSAMP_GRAY);

  if (tj3Transform(handle, data, size, 1, dstBufs, dstSizes, transforms) == 0) {
    size_t sum = 0;
    for (i = 0; i < dstSizes[0]; i++) sum += dstBufs[0][i];
    if (sum > 255 * maxBufSize) goto bailout;
  }

  free(dstBufs[0]); dstBufs[0] = NULL;

  // -------- Third transform (rotate + trim + subsamp change) --------
  transforms[0].op = TJXOP_ROT90;
  transforms[0].options = TJXOPT_TRIM | TJXOPT_ARITHMETIC;
  dstSubsamp = jpegSubsamp;
  if (dstSubsamp == TJSAMP_422) dstSubsamp = TJSAMP_440;
  else if (dstSubsamp == TJSAMP_440) dstSubsamp = TJSAMP_422;
  else if (dstSubsamp == TJSAMP_411) dstSubsamp = TJSAMP_441;
  else if (dstSubsamp == TJSAMP_441) dstSubsamp = TJSAMP_411;

  dstBufs[0] = (unsigned char *)tj3Alloc(tj3JPEGBufSize(height, width, dstSubsamp));
  if (!dstBufs[0]) goto bailout;

  maxBufSize = tj3JPEGBufSize(height, width, dstSubsamp);

  if (tj3Transform(handle, data, size, 1, dstBufs, dstSizes, transforms) == 0) {
    size_t sum = 0;
    for (i = 0; i < dstSizes[0]; i++) sum += dstBufs[0][i];
    if (sum > 255 * maxBufSize) goto bailout;
  }

  free(dstBufs[0]); dstBufs[0] = NULL;

  // -------- Fourth transform (progressive with realloc) --------
  transforms[0].op = TJXOP_NONE;
  transforms[0].options = TJXOPT_PROGRESSIVE;
  dstSizes[0] = 0;
  tj3Set(handle, TJPARAM_NOREALLOC, 0);

  if (tj3Transform(handle, data, size, 1, dstBufs, dstSizes, transforms) == 0) {
    size_t sum = 0;
    for (i = 0; i < dstSizes[0]; i++) sum += dstBufs[0][i];
    if (sum > 255 * maxBufSize) goto bailout;
  }

bailout:
  if (dstBufs[0]) tj3Free(dstBufs[0]);
  tj3Destroy(handle);
  return 0;
}
