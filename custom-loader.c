#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "custom-loader.h"

// Uses ELF Format.  For background, read both of:
//  * http://www.skyfree.org/linux/references/ELF_Format.pdf
//  * /usr/include/elf.h
// The kernel code is here (not recommended for a first reading):
//    https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c

static void get_elf_interpreter(int , Elf64_Addr *, char* , void* );
static void* load_elf_interpreter(int , char* , Elf64_Addr *, void * );
static void* map_elf_interpreter_load_segment(int , Elf64_Phdr , void * );

// Global functions
DynObjInfo_t
safeLoadLib(const char *name)
{
  void *ld_so_addr = NULL;
  DynObjInfo_t info = {0};

  int ld_so_fd;
  Elf64_Addr cmd_entry, ld_so_entry;
  char elf_interpreter[MAX_ELF_INTERP_SZ];

  // FIXME: Do we need to make it dynamic? Is setting this required?
  ld_so_addr = (void*)0x7ffff81d5000;
  int cmd_fd = open(name, O_RDONLY);
  get_elf_interpreter(cmd_fd, &cmd_entry, elf_interpreter, ld_so_addr);
  // FIXME: The ELF Format manual says that we could pass the cmd_fd to ld.so,
  //   and it would use that to load it.
  close(cmd_fd);
#ifndef UBUNTU
   strncpy(elf_interpreter, name, sizeof elf_interpreter);
#endif

  ld_so_fd = open(elf_interpreter, O_RDONLY);
  info.baseAddr = load_elf_interpreter(ld_so_fd, elf_interpreter,
                                        &ld_so_entry, ld_so_addr);
  // FIXME: The ELF Format manual says that we could pass the ld_so_fd to ld.so,
  //   and it would use that to load it.
  close(ld_so_fd);
  info.entryPoint = (void*)((unsigned long)info.baseAddr +
                            (unsigned long)cmd_entry);
  return info;
}


// Local functions
static void
get_elf_interpreter(int fd, Elf64_Addr *cmd_entry,
                    char* elf_interpreter, void *ld_so_addr)
{
  int rc;
  char e_ident[EI_NIDENT];

  rc = read(fd, e_ident, sizeof(e_ident));
  assert(rc == sizeof(e_ident));
  assert(strncmp(e_ident, ELFMAG, strlen(ELFMAG)) == 0);
  assert(e_ident[EI_CLASS] == ELFCLASS64); // FIXME:  Add support for 32-bit ELF

  // Reset fd to beginning and parse file header
  lseek(fd, 0, SEEK_SET);
  Elf64_Ehdr elf_hdr;
  rc = read(fd, &elf_hdr, sizeof(elf_hdr));
  assert(rc == sizeof(elf_hdr));
  *cmd_entry = elf_hdr.e_entry;

  // Find ELF interpreter
  int i;
  Elf64_Phdr phdr;
  int phoff = elf_hdr.e_phoff;

  lseek(fd, phoff, SEEK_SET);
  for (i = 0; i < elf_hdr.e_phnum; i++) {
    assert(i < elf_hdr.e_phnum);
    rc = read(fd, &phdr, sizeof(phdr)); // Read consecutive program headers
#ifdef UBUNTU
    if (phdr.p_type == PT_INTERP) break;
  }
  lseek(fd, phdr.p_offset, SEEK_SET); // Point to beginning of elf interpreter
  assert(phdr.p_filesz < MAX_ELF_INTERP_SZ);
  rc = read(fd, elf_interpreter, phdr.p_filesz);
  assert(rc == phdr.p_filesz);

  DLOG(INFO, "Interpreter: %s\n", elf_interpreter);
  { char buf[256] = "/usr/lib/debug";
    buf[sizeof(buf)-1] = '\0';
    int rc = 0;
    rc = readlink(elf_interpreter, buf+strlen(buf), sizeof(buf)-strlen(buf)-1);
    if (rc != -1 && access(buf, F_OK) == 0) {
      // Debian family (Ubuntu, etc.) use this scheme to store debug symbols.
      //   http://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
      DLOG(INFO, "Debug symbols for interpreter in: %s\n", buf);
    }
  }
#else // ifdef UBUNTU
  }
#endif // ifdef UBUNTU
}

static void*
load_elf_interpreter(int fd, char *elf_interpreter,
                     Elf64_Addr *ld_so_entry, void *ld_so_addr)
{
  char e_ident[EI_NIDENT];
  int rc;
  int firstTime = 1;
  void *baseAddr = NULL;

  rc = read(fd, e_ident, sizeof(e_ident));
  assert(rc == sizeof(e_ident));
  assert(strncmp(e_ident, ELFMAG, sizeof(ELFMAG)-1) == 0);
  // FIXME:  Add support for 32-bit ELF later
  assert(e_ident[EI_CLASS] == ELFCLASS64);

  // Reset fd to beginning and parse file header
  lseek(fd, 0, SEEK_SET);
  Elf64_Ehdr elf_hdr;
  rc = read(fd, &elf_hdr, sizeof(elf_hdr));
  assert(rc == sizeof(elf_hdr));

  // Find ELF interpreter
  int phoff = elf_hdr.e_phoff;
  Elf64_Phdr phdr;
  int i;
  lseek(fd, phoff, SEEK_SET);
  for (i = 0; i < elf_hdr.e_phnum; i++ ) {
    rc = read(fd, &phdr, sizeof(phdr)); // Read consecutive program headers
    if (phdr.p_type == PT_LOAD) {
      // PT_LOAD is the only type of loadable segment for ld.so
      if (firstTime) {
        baseAddr = map_elf_interpreter_load_segment(fd, phdr, ld_so_addr);
        firstTime = 0;
      } else {
        map_elf_interpreter_load_segment(fd, phdr, ld_so_addr);
      }
    }
  }
  return baseAddr;
}

static void*
map_elf_interpreter_load_segment(int fd, Elf64_Phdr phdr, void *ld_so_addr)
{
  static char *base_address = NULL; // is NULL on call to first LOAD segment
  static int first_time = 1;
  int prot = PROT_NONE;
  if (phdr.p_flags & PF_R)
    prot |= PROT_READ;
  if (phdr.p_flags & PF_W)
    prot |= PROT_WRITE;
  if (phdr.p_flags & PF_X)
    prot |= PROT_EXEC;
  assert(phdr.p_memsz >= phdr.p_filesz);
  // NOTE:  man mmap says:
  // For a file that is not a  multiple  of  the  page  size,  the
  // remaining memory is zeroed when mapped, and writes to that region
  // are not written out to the file.
  void *rc2;
  // Check ELF Format constraint:
  if (phdr.p_align > 1) {
    assert(phdr.p_vaddr % phdr.p_align == phdr.p_offset % phdr.p_align);
  }
  int vaddr = phdr.p_vaddr;
  phdr.p_vaddr = ROUND_DOWN(phdr.p_vaddr);
  phdr.p_offset = ROUND_DOWN(phdr.p_offset);
  phdr.p_memsz = phdr.p_memsz + (vaddr - phdr.p_vaddr);
  // NOTE:  base_address is 0 for first load segment
  if (first_time) {
    phdr.p_vaddr += (unsigned long long)ld_so_addr;
  } else {
    phdr.p_vaddr += (unsigned long long)base_address;
  }
  // FIXME:  On first load segment, we should map 0x400000 (2*phdr.p_align),
  //         and then unmap the unused portions later after all the
  //         LOAD segments are mapped.  This is what ld.so would do.
  if (first_time && ld_so_addr == NULL) {
    rc2 = mmap((void *)phdr.p_vaddr, phdr.p_memsz,
               prot, MAP_PRIVATE, fd, phdr.p_offset);
   } else {
    rc2 = mmap((void *)phdr.p_vaddr, phdr.p_memsz,
               prot, MAP_PRIVATE|MAP_FIXED, fd, phdr.p_offset);
   }
  if (rc2 == MAP_FAILED) {
    DLOG(ERROR, "Failed to map memory region at %p. Error:%s\n",
         (void*)phdr.p_vaddr, strerror(errno));
    return NULL;
  }
  // Required by ELF Format:
  if (phdr.p_memsz > phdr.p_filesz) {
    memset((char *)rc2 + phdr.p_filesz, '\0', phdr.p_memsz - phdr.p_filesz);
  }
  if (first_time) {
    first_time = 0;
    base_address = rc2;
  }
  return base_address;
}
