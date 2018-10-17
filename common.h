#ifndef COMMON_H
#define COMMON_H

#ifndef DEBUG_LEVEL
# define DEBUG_LEVEL 1
#endif // ifndef DEBUG_LEVEL

#define NOISE 3 // Noise!
#define INFO  2 // Informational logs
#define ERROR 1 // Highest error/exception level

#ifndef RTLD
# define RTLD        "/lib64/ld-2.27.so"
# warning "Using /lib64/ld-2.27.so as the runtime loader. Update if necessary."
#endif // ifndef RTLD

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

// FIXME: 0x1000 is one page; Use sysconf(PAGESIZE) instead.
#define ROUND_DOWN(x) ((unsigned long long)(x) \
                      & ~(unsigned long long)(0x1000-1))

#endif // ifndef COMMON_H
