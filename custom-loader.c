#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
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
static void* load_elf_interpreter(int , char* ,
                                  void * , DynObjInfo_t* );
off_t get_symbol_offset(const char* , const char* );
static void* map_elf_interpreter_load_segment(int , Elf64_Phdr , void* );

static int getSymbolTable(const char* , Elf64_Shdr* , char** );
static int readElfSection(int , int , const Elf64_Ehdr* ,
                          Elf64_Shdr* , char **);

// Global functions
DynObjInfo_t
safeLoadLib(const char *name)
{
  void *ld_so_addr = NULL;
  DynObjInfo_t info = {0};

  int ld_so_fd;
  Elf64_Addr cmd_entry, ld_so_entry;
  char elf_interpreter[PATH_MAX];

  // FIXME: Do we need to make it dynamic? Is setting this required?
  // ld_so_addr = (void*)0x7ffff81d5000;
  // ld_so_addr = (void*)0x7ffff7dd7000;
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
                                       ld_so_addr, &info);
  info.mmapAddr = info.baseAddr + get_symbol_offset(name, "mmap");
  info.sbrkAddr = info.baseAddr + get_symbol_offset(name, "sbrk");
  // FIXME: The ELF Format manual says that we could pass the ld_so_fd to ld.so,
  //   and it would use that to load it.
  close(ld_so_fd);
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

// Returns offset of symbol, or -1 on failure.
off_t
get_symbol_offset(const char *libname, const char *symbol)
{
  int rc;
  Elf64_Shdr symtab;
  Elf64_Sym symtab_entry;

  off_t result = -1;
  char *strtab = NULL;

  int fd = getSymbolTable(libname, &symtab, &strtab);
  if (fd < 0) {
    DLOG(ERROR, "Failed to file debug symbol file for %s\n", libname);
    return -1;
  }

  // Move to beginning of symbol table
  lseek(fd, symtab.sh_offset, SEEK_SET);
  for ( ; lseek(fd, 0, SEEK_CUR) - symtab.sh_offset < symtab.sh_size; ) {
    rc = read(fd, &symtab_entry, sizeof symtab_entry);
    assert(rc == sizeof(symtab_entry));
    if (strcmp(strtab + symtab_entry.st_name, symbol) == 0) {
      // found address as offset from base address
      result = symtab_entry.st_value;
      break;
    }
  }
  if (strtab) {
    free(strtab);
  }
  close(fd);
  if (result == -1) {
    DLOG(ERROR, "Failed to find symbol (%s) in %s\n", symbol, libname);
  }
  return result;
}

static void*
load_elf_interpreter(int fd, char *elf_interpreter,
                     void *ld_so_addr, DynObjInfo_t *info)
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
  info->phnum = elf_hdr.e_phnum;
  info->phdr = baseAddr + elf_hdr.e_phoff;
  info->entryPoint = baseAddr + elf_hdr.e_entry;
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

  int flags = MAP_PRIVATE;
  unsigned long addr = ROUND_DOWN(base_address + vaddr);
  size_t size = ROUND_UP(phdr.p_filesz + PAGE_OFFSET(phdr.p_vaddr));
  off_t offset = phdr.p_offset - PAGE_OFFSET(phdr.p_vaddr);

  // phdr.p_vaddr = ROUND_DOWN(phdr.p_vaddr);
  // phdr.p_offset = ROUND_DOWN(phdr.p_offset);
  // phdr.p_memsz = phdr.p_memsz + (vaddr - phdr.p_vaddr);
  // NOTE:  base_address is 0 for first load segment
  if (first_time) {
    phdr.p_vaddr += (unsigned long long)ld_so_addr;
  } else {
    flags |= MAP_FIXED;
  }
  if (ld_so_addr) {
    flags |= MAP_FIXED;
  }
  // FIXME:  On first load segment, we should map 0x400000 (2*phdr.p_align),
  //         and then unmap the unused portions later after all the
  //         LOAD segments are mapped.  This is what ld.so would do.
  rc2 = mmap((void *)addr, size, prot, MAP_PRIVATE, fd, offset);
  if (rc2 == MAP_FAILED) {
    DLOG(ERROR, "Failed to map memory region at %p. Error:%s\n",
         (void*)addr, strerror(errno));
    return NULL;
  }
  unsigned long startBss = (uintptr_t)base_address +
                          phdr.p_vaddr + phdr.p_filesz;
  unsigned long endBss = (uintptr_t)base_address + phdr.p_vaddr + phdr.p_memsz;
  // Required by ELF Format:
  if (phdr.p_memsz > phdr.p_filesz) {
    // This condition is true for the RW (data) segment of ld.so
    // We need to clear out the rest of memory contents, similarly to
    // what the kernel would do. See here:
    //   https://elixir.bootlin.com/linux/v4.18.11/source/fs/binfmt_elf.c#L905
    // Note that p_memsz indicates end of data (&_end)

    // First, get to the page boundary
    uintptr_t endByte = ROUND_UP(startBss);
    // Next, figure out the number of bytes we need to clear out.
    // From Bss to the end of page.
    size_t bytes = endByte - startBss;
    memset((void*)startBss, 0, bytes);
  }
  // If there's more bss that overflows to another page, map it in and
  // zero it out
  startBss  = ROUND_UP(startBss);
  endBss    = ROUND_UP(endBss);
  if (endBss > startBss) {
    void *base = (void*)startBss;
    size_t len = endBss - startBss;
    flags |= MAP_ANONYMOUS; // This should give us 0-ed out pages
    rc2 = mmap(base, len, prot, flags, -1, 0);
    if (rc2 == MAP_FAILED) {
      DLOG(ERROR, "Failed to map memory region at %p. Error:%s\n",
           (void*)startBss, strerror(errno));
      return NULL;
    }
  }
  if (first_time) {
    first_time = 0;
    base_address = rc2;
  }
  return base_address;
}

// On success, returns fd of debug file, pointers to symtab and strtab
// On failures, returns -1
static int
getSymbolTable(const char *libname, Elf64_Shdr *symtab, char **strtab)
{
  int rc;
  int fd = -1;
  int retries = 0;
  int symtab_found = 0;
  int foundDebugLib = 0;
  char debugLibName[PATH_MAX] = {0};

  char *shsectData = NULL;
  char *lname = (char*)libname;

  Elf64_Shdr sect_hdr;

  while (retries < 2) {
    fd = open(lname, O_RDONLY);

    // Reset fd to beginning and parse file header
    lseek(fd, 0, SEEK_SET);
    Elf64_Ehdr elf_hdr;
    rc = read(fd, &elf_hdr, sizeof(elf_hdr));
    assert(rc == sizeof(elf_hdr));

    // Get start of symbol table and string table
    Elf64_Off shoff = elf_hdr.e_shoff;

    // First, read the data from the shstrtab section
    // This section contains the strings corresponding to the section names
    rc = readElfSection(fd, elf_hdr.e_shstrndx,
                           &elf_hdr, &sect_hdr, &shsectData);

    lseek(fd, shoff, SEEK_SET);
    for (int i = 0; i < elf_hdr.e_shnum; i++) {
      rc = read(fd, &sect_hdr, sizeof sect_hdr);
      assert(rc == sizeof(sect_hdr));
      if (sect_hdr.sh_type == SHT_SYMTAB) {
        *symtab = sect_hdr;
        symtab_found = 1;
      } else if (sect_hdr.sh_type == SHT_STRTAB &&
                 !strcmp(&shsectData[sect_hdr.sh_name], ELF_STRTAB_SECT)) {
        // Note that there are generally three STRTAB sections in ELF binaries:
        //  1. .dynstr
        //  2. .shstrtab
        //  3. .strtab
        // We only care about the strtab section.
        Elf64_Shdr tmp;
        rc = readElfSection(fd, i, &elf_hdr, &tmp, strtab);
      } else if (sect_hdr.sh_type == SHT_PROGBITS &&
                 !strcmp(&shsectData[sect_hdr.sh_name], ELF_DEBUGLINK_SECT)) {
        // If it's the ".gnu_debuglink" section, we read it to figure out
        // the path to the debug symbol file
        Elf64_Shdr tmp;
        char *debugName = NULL;
        rc = readElfSection(fd, i, &elf_hdr, &tmp, &debugName);
        assert(debugName);
        snprintf(debugLibName, sizeof debugLibName, "%s/%s",
                 DEBUG_FILES_PATH, debugName);
        free(debugName);
        foundDebugLib = 1;
      }
    }

    if (symtab_found || !foundDebugLib) {
      break;
    }

    // Let's try again with debug library
    lname = debugLibName;
    DLOG(INFO, "Failed to find symbol table in %s. Retrying with %s...\n",
         libname, lname);
    retries++;
  }
  free(shsectData);
  if (retries == 2 && !symtab_found) {
    DLOG(ERROR, "Failed to find symbol table in %s\n", libname);
    close(fd);
    return -1;
  }
  return fd;
}

static int
readElfSection(int fd, int sidx, const Elf64_Ehdr *ehdr,
               Elf64_Shdr *shdr, char **data)
{
  off_t currOff = lseek(fd, 0, SEEK_CUR);
  off_t sidx_off = ehdr->e_shentsize * sidx + ehdr->e_shoff;
  lseek(fd, sidx_off, SEEK_SET);
  int rc = read(fd, shdr, sizeof *shdr);
  assert(rc == sizeof *shdr);
  rc = lseek(fd, shdr->sh_offset, SEEK_SET);
  if (rc > 0) {
    *data = malloc(shdr->sh_size);
    rc = lseek(fd, shdr->sh_offset, SEEK_SET);
    rc = read(fd, *data, shdr->sh_size);
    assert(rc == shdr->sh_size);
  }
  lseek(fd, currOff, SEEK_SET);
  return *data != NULL ? 0 : -1;
}
