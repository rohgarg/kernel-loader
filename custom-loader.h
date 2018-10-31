#ifndef CUSTOM_LOADER_H
#define CUSTOM_LOADER_H

#define MMAP_SYMBOL_NAME     "mmap"
#define SBRK_SYMBOL_NAME     "sbrk"
#define ELF_STRTAB_SECT      ".strtab"
#define ELF_DEBUGLINK_SECT   ".gnu_debuglink"

// FIXME: Find this path at runtime?
#define DEBUG_FILES_PATH   "/usr/lib/debug/lib/x86_64-linux-gnu"

typedef struct __DynObjInfo
{
  void *baseAddr;
  void *entryPoint;
  uint64_t phnum;
  void *phdr;
  void *mmapAddr;
  void *sbrkAddr;
} DynObjInfo_t;

DynObjInfo_t safeLoadLib(const char *);

#endif // ifndef CUSTOM_LOADER_H
