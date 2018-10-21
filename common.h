#ifndef COMMON_H
#define COMMON_H

#include <link.h>
#include <string.h>

// Logging levels
#define NOISE 3 // Noise!
#define INFO  2 // Informational logs
#define ERROR 1 // Highest error/exception level

#ifndef DEBUG_LEVEL
// Let's announce errors out loud
# define DEBUG_LEVEL 1
#endif // ifndef DEBUG_LEVEL

#define VA_ARGS(...)  , ##__VA_ARGS__
#define DLOG(LOG_LEVEL, fmt, ...)                                              \
do {                                                                           \
  if (DEBUG_LEVEL) {                                                           \
    if (LOG_LEVEL <= DEBUG_LEVEL)                                              \
      fprintf(stderr, "[%s +%d]: " fmt, __FILE__,                              \
              __LINE__ VA_ARGS(__VA_ARGS__));                                  \
  }                                                                            \
} while(0)

// Based on the entries in /proc/<pid>/stat as described in `man 5 proc`
enum Procstat_t
{
   PID = 1,
   COMM,   // 2
   STATE,  // 3
   PPID,   // 4
   NUM_THREADS = 19,
   STARTSTACK = 27,
};

#define PAGE_SIZE 0x1000ULL

// FIXME: 0x1000 is one page; Use sysconf(PAGESIZE) instead.
#define ROUND_DOWN(x) ((unsigned long long)(x) \
                      & ~(unsigned long long)(PAGE_SIZE - 1))
#define ROUND_UP(x)  (((unsigned long long)(x) + PAGE_SIZE - 1) & \
                      ~(PAGE_SIZE - 1))
#define PAGE_OFFSET(x)  ((x) & (PAGE_SIZE - 1))

// TODO: This is very x86-64 specific; support other architectures??
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

// Returns pointer to argc, given a pointer to end of stack
static inline void*
GET_ARGC_ADDR(const void* stackEnd)
{
  return (void*)((uintptr_t)(stackEnd) + sizeof(uintptr_t));
}

// Returns pointer to argv[0], given a pointer to end of stack
static inline void*
GET_ARGV_ADDR(const void* stackEnd)
{
  return (void*)((unsigned long)(stackEnd) + 2 * sizeof(uintptr_t));
}

// Returns pointer to env[0], given a pointer to end of stack
static inline void*
GET_ENV_ADDR(char **argv, int argc)
{
  return (void*)&argv[argc + 1];
}

// Returns a pointer to aux vector, given a pointer to the environ vector
// on the stack
static inline ElfW(auxv_t)*
GET_AUXV_ADDR(const char **env)
{
  ElfW(auxv_t) *auxvec;
  const char **evp = env;
  while (*evp++ != NULL);
  auxvec = (ElfW(auxv_t) *) evp;
  return auxvec;
}

void runRtld();
void* sbrkWrapper(intptr_t );
void* mmapWrapper(void *, size_t , int , int , int , off_t );
void* getEndofHeap();
void setEndOfHeap(void *);

#endif // ifndef COMMON_H
