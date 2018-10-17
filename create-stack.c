#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "common.h"
#include "custom-loader.h"
#include "procmapsutils.h"

#define eax rax
#define ebx rbx
#define ecx rcx
#define edx rax
#define ebp rbp
#define esi rsi
#define edi rdi
#define esp rsp
#define CLEAN_FOR_64_BIT_HELPER(args ...) # args
#define CLEAN_FOR_64_BIT(args ...)        CLEAN_FOR_64_BIT_HELPER(args)

// Helper macro to get pointers to argc, argv[0], and env[0], given
// a pointer to the end of stack
#define GET_ARGC_ADDR(end)          (unsigned long)(end) + sizeof(unsigned long)
#define GET_ARGV_ADDR(end)          (unsigned long)(end) + 2 * sizeof(unsigned long)
#define GET_ENV_ADDR(argv, argc)    &(argv)[(argc) + 1]

// Pointer to the ldso_entrypoint
static void *ldso_entrypoint;
void runRtld();

// Local functions
static void getProcStatField(enum Procstat_t , char *, size_t );
static void getStackRegion(Area *);
static void deepCopyStack(void *, const void *, size_t,
                          const void *, const void*);
static void* createNewStackForRtld();
static void* getEntryPoint(DynObjInfo_t );
static inline ElfW(auxv_t)* GET_AUXV_ADDR(char **env);
static void patchAuxv(ElfW(auxv_t) *, unsigned long , unsigned long , int );

// Global functions

// This function loads in ld.so, sets up a separate stack for it, and jumps
// to the entry point of ld.so
void
runRtld()
{
  // Load RTLD (ld.so)
  DynObjInfo_t ldso = safeLoadLib(RTLD);
  if (ldso.baseAddr == NULL || ldso.entryPoint == NULL) {
    DLOG(ERROR, "Error loading the runtime loader (%s). Exiting...\n", RTLD);
    return;
  }
  ldso_entrypoint = getEntryPoint(ldso);
  // Create new stack region to be used by RTLD
  void *newStack = createNewStackForRtld();
  if (!newStack) {
    DLOG(ERROR, "Error creating new stack for RTLD. Exiting...\n");
    exit(-1);
  }
  asm volatile (CLEAN_FOR_64_BIT(mov %0, %%esp; )
                : : "g" (newStack) : "memory");
  asm volatile ("jmp *%0" : : "g" (ldso_entrypoint) : "memory");
}

#ifdef STANDALONE
int
main(int argc, char **argv)
{
  runRtld();
  return 0;
}
#endif

// Returns the /proc/self/stat entry in the out string (of length len)
static void
getProcStatField(enum Procstat_t type, char *out, size_t len)
{
  const char *procPath = "/proc/self/stat";
  char sbuf[1024] = {0};
  int field_counter = 0;
  char *field_str = NULL;
  int fd, num_read;

  fd = open(procPath, O_RDONLY);

  num_read = read(fd, sbuf, sizeof sbuf - 1);
  close(fd);
  if (num_read <= 0) return;
  sbuf[num_read] = '\0';

  field_str = strtok(sbuf, " ");
  while (field_str != NULL && field_counter != type) {
    if (field_counter == type) {
      break;
    }
    field_str = strtok(NULL, " ");
    field_counter++;
  }

  strncpy(out, field_str, len);
}

// Returns the [stack] area by reading the proc maps
static void
getStackRegion(Area *stack) // OUT
{
  Area area;
  int mapsfd = open("/proc/self/maps", O_RDONLY);
  while (readMapsLine(mapsfd, &area)) {
    if (strstr(area.name, "[stack]") && area.endAddr >= (VA)&area) {
      *stack = area;
      break;
    }
  }
  close(mapsfd);
}

// Returns a pointer to aux vector, given a pointer to the environ vector
// on the stack
static inline ElfW(auxv_t)*
GET_AUXV_ADDR(char **env)
{
  ElfW(auxv_t) *auxvec;
  char **evp = env;
  while (*evp++ != NULL);
  auxvec = (ElfW(auxv_t) *) evp;
  return auxvec;
}

// Given a pointer to auxvector, parses the aux vector and patches the AT_PHDR
// and AT_PHNUM entries. If save is set, it saves original entries in
// local, static variables. If save is not set, the original entries are
// restored.
// 
// XXX: This is not used anywhere right now, but it's here for use in the
// future.
static void
patchAuxv(ElfW(auxv_t) *av, unsigned long phnum, unsigned long phdr, int save)
{
  static unsigned long origPhnum;
  static unsigned long origPhdr;

  for (; av->a_type != AT_NULL; ++av) {
    switch (av->a_type) {
      case AT_PHNUM:
        if (save) {
          origPhnum = av->a_un.a_val;
          av->a_un.a_val = phnum;
        } else {
          av->a_un.a_val = origPhnum;
        }
        break;
      case AT_PHDR:
        if (save) {
         origPhdr = av->a_un.a_val;
         av->a_un.a_val = phdr;
        } else {
          av->a_un.a_val = origPhdr;
        }
        break;
      default:
        break;
    }
  }
}

// Creates a deep copy of the stack region pointed to be `origStack` at the
// location pointed to be `newStack`.
static void
deepCopyStack(void *newStack, const void *origStack, size_t len,
              const void *newStackEnd, const void *origStackEnd)
{
  // The main thing to do is patch the argv and env vectors in the stack to
  // point to addresses in the new stack region. Note that the argv and env
  // are simply arrays of pointers. The pointers point to strings in other
  // locationsi in the stack
  memcpy(newStack, origStack, len);

  void *origArgcAddr = (void*)GET_ARGC_ADDR(origStackEnd);
  int  origArgc      = *(int*)origArgcAddr;
  char **origArgv    = (void*)GET_ARGV_ADDR(origStackEnd);
  char **origEnv     = (void*)GET_ENV_ADDR(origArgv, origArgc);
  ElfW(auxv_t) *origAuxv = GET_AUXV_ADDR(origEnv);

  void *newArgcAddr = (void*)GET_ARGC_ADDR(newStackEnd);
  int  newArgc      = *(int*)newArgcAddr;
  char **newArgv    = (void*)GET_ARGV_ADDR(newStackEnd);
  char **newEnv     = (void*)GET_ENV_ADDR(newArgv, newArgc);
  ElfW(auxv_t) *newAuxv = GET_AUXV_ADDR(newEnv);

  // Patch the argv vector in the new stack
  for (int i = 0; origArgv[i] != NULL; i++) {
    off_t argvDelta = (uintptr_t)origArgv[i] - (uintptr_t)origArgv;
    newArgv[i] = (char*)((uintptr_t)newArgv + (uintptr_t)argvDelta);
  }
  // FIXME: This needs to be fixed. We have to get two arguments on the stack:
  // The first argument needs to be RTLD and the second argument needs to be
  // the target executable.
  char *ptr = strstr(newArgv[0], "a.out");
  if (ptr != 0) {
    ptr[0] = 't'; // Replace a.out with t.out
  }

  // Patch the env vector in the new stack
  for (int i = 0; origEnv[i] != NULL; i++) {
    off_t envDelta = (uintptr_t)origEnv[i] - (uintptr_t)origEnv;
    newEnv[i] = (char*)((uintptr_t)newEnv + (uintptr_t)envDelta);
  }
}

// This function does three things:
//  1. Creates a new stack region to be used for initialization of RTLD (ld.so)
//  2. Deep copies the original stack (from the kernel) in the new stack region
//  3. Returns a pointer to the beginning of stack in the new stack region
static void*
createNewStackForRtld()
{
  Area stack;
  char stackEndStr[20] = {0};
  getStackRegion(&stack);

  // 1. Allocate new stack region
  void *newStack = mmap(NULL, stack.size, PROT_READ | PROT_WRITE,
                        MAP_GROWSDOWN | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (newStack == MAP_FAILED) {
    DLOG(ERROR, "Failed to mmap new stack region: %s\n", strerror(errno));
    return NULL;
  }

  // 3. Get pointer to the beginning of the stack in the new stack region
  // The idea here is to look at the beginning of stack in the original
  // stack region, and use that to index into the new memory region. The
  // same offsets are valid in both the stack regions.
  getProcStatField(STARTSTACK, stackEndStr, sizeof stackEndStr);

  // NOTE: The kernel sets up the stack in the following format.
  //      0(%rsp)                        NULL (Stack Start for Application)
  //      LP_SIZE(%rsp)                  argc
  //      (2*LP_SIZE)(%rsp)              argv[0]
  //      ...
  //      (LP_SIZE*(argc+1))(%rsp)       NULL
  //      (LP_SIZE*(argc+2))(%rsp)       envp[0]
  //      ...
  //                                     NULL
  //
  // NOTE: proc-stat returns the address of argc on the stack.
  // argv[0] is 1 LP_SIZE ahead of argc, i.e., startStack + sizeof(void*)
  // Stack End is 1 LP_SIZE behind argc, i.e., startStack - sizeof(void*)
  // sizeof(unsigned long) == sizeof(void*) == 8 on x86-64
  unsigned long origStackEnd = atol(stackEndStr) - sizeof(unsigned long);
  unsigned long origStackOffset = origStackEnd - (unsigned long)stack.addr;
  unsigned long newStackOffset = origStackOffset;
  void *newStackEnd = (void*)((unsigned long)newStack + newStackOffset);

  // 2. Deep copy stack
  deepCopyStack(newStack, stack.addr, stack.size,
                (void*)newStackEnd, (void*)origStackEnd);

  return newStackEnd;
}

// This function returns the entry point of the ld.so executable given
// the library handle
static void*
getEntryPoint(DynObjInfo_t info)
{
  return info.entryPoint;
}

