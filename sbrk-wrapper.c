#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#include "common.h"

static void *__curbrk;
static void *__endOfHeap = 0;

void*
getEndOfHeap()
{
  return __curbrk;
}

void
setEndOfHeap(void *addr)
{
  __curbrk = addr;
  __endOfHeap = (void*)ROUND_UP(__curbrk);
}


/* Extend the process's data space by INCREMENT.
   If INCREMENT is negative, shrink data space by - INCREMENT.
   Return start of new space allocated, or -1 for errors.  */
void*
sbrkWrapper(intptr_t increment)
{
  void *oldbrk;

  if (__curbrk == NULL)
    if (brk (0) < 0)
      return (void *) -1;
    else
      __endOfHeap = __curbrk;

  if (increment == 0)
    return __curbrk;

  oldbrk = __curbrk;
  if (increment > 0
      ? ((uintptr_t) oldbrk + (uintptr_t) increment < (uintptr_t) oldbrk)
      : ((uintptr_t) oldbrk < (uintptr_t) -increment))
    {
      errno = ENOMEM;
      return (void *) -1;
    }

  if (oldbrk + increment > __endOfHeap) {
    if (mmap(__endOfHeap, ROUND_UP(oldbrk + increment - __endOfHeap),
             PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
             -1, 0) < 0) {
       return (void *) -1;
    }
  }

  __endOfHeap = (void*)ROUND_UP(oldbrk + increment);
  __curbrk = oldbrk + increment;

  return oldbrk;
}
