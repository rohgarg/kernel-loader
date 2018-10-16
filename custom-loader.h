#ifndef CUSTOM_LOADER_H
#define CUSTOM_LOADER_H

#define MAX_ELF_INTERP_SZ 256

typedef struct __DynObjInfo
{
  void *baseAddr;
  void *entryPoint;
} DynObjInfo_t;

DynObjInfo_t safeLoadLib(const char *);

#endif // ifndef CUSTOM_LOADER_H
