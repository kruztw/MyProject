#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#define MAX_FILENAME_SIZE (255)

char *file_addr;
char *sh_strtab_p;
char *sh_dynstr_p;

Elf64_Ehdr *ehdr;
Elf64_Phdr *phdr;
Elf64_Shdr *shdr, *sh_strtab, *sh_gnu_hash, *sh_dynamic, *sh_dynstr, *sh_dynsym, \
           *sh_gnu_version, *sh_gnu_version_r;

int i, j, k, l;

void usage(char **argv)
{
    printf("Usage: %s <elf>\n", argv[0]);
    exit(-1);
}

static const char *get_elf_class(unsigned int elf_class)
{
    switch (elf_class) {
        case ELFCLASSNONE: return "none";
        case ELFCLASS32:   return "ELF32 (not support)";
        case ELFCLASS64:   return "ELF64";
        default:           return "unknown";
    }
}

static const char *get_data_encoding(unsigned int encoding)
{
    switch (encoding) {
        case ELFDATANONE: return "none";
        case ELFDATA2LSB: return "2's complement, little endian";
        case ELFDATA2MSB: return "2's complement, big endian (not support)";
        default:          return "unknown";
    }
}

static const char *get_elf_version(unsigned int version)
{
    switch (version) {
        case EV_CURRENT: return "current";
        default        : return "unknown";
    }
}

static const char *get_osabi_name(unsigned int osabi)
{
    switch (osabi) {
        case ELFOSABI_NONE:     return "UNIX - System V";
        default:                return "not supported";
    }
}

static const char *get_file_type(unsigned int e_type)
{
    switch (e_type) {
        case ET_NONE: return "NONE (None)";
        case ET_REL:  return "REL (Relocatable file)";
        case ET_EXEC: return "EXEC (Executable file)";
        case ET_DYN:  return "DYN (Shared object file)";
        case ET_CORE: return "CORE (Core file)";
        default:      return "not supported";
    }
}

static const char *get_machine_name(unsigned e_machine)
{
    return "TBD";
}

static char *get_machine_flags(unsigned e_flags, unsigned e_machine)
{
    static char buf[1024];
    buf[0] = '\0';

    if (e_flags)
        strcat(buf, "TBD");

    return buf;
}


void process_file_header()
{
    printf("  Magic:   ");
    for (i = 0; i < EI_NIDENT; i++)
        printf("%2.2x ", ehdr->e_ident[i]);

    printf("\n");
    printf("  Class:                             %s\n"                    , get_elf_class(ehdr->e_ident[EI_CLASS]));
    printf("  Data:                              %s\n"                    , get_data_encoding(ehdr->e_ident[EI_DATA]));
    printf("  Version:                           %d (%s)\n"               , ehdr->e_ident[EI_VERSION], get_elf_version(ehdr->e_ident[EI_VERSION]));  
    printf("  OS/ABI:                            %s\n"                    , get_osabi_name(ehdr->e_ident[EI_OSABI]));
    printf("  ABI Version:                       %d\n"                    , ehdr->e_ident[EI_ABIVERSION]);
    printf("  Type:                              %s\n"                    , get_file_type(ehdr->e_type));
    printf("  Version:                           0x%x\n"                  , ehdr->e_version);
    printf("  Machine:                           %s\n"                    , get_machine_name(ehdr->e_machine));
    printf("  Entry point address:               0x%lx\n"                 , ehdr->e_entry);
    printf("  Start of program headers:          %ld (bytes into file)\n" , ehdr->e_phoff);
    printf("  Start of section headers:          %ld (bytes into file)\n" , ehdr->e_shoff);
    printf("  Flags:                             0x%x%s\n"                , ehdr->e_flags, get_machine_flags(ehdr->e_flags, ehdr->e_machine));
    printf("  Size of this header:               %u (bytes)\n"            , ehdr->e_ehsize);
    printf("  Size of program headers:           %u (bytes)\n"            , ehdr->e_phentsize);
    printf("  Number of program headers:         %u\n"                    , ehdr->e_phnum);
    printf("  Size of section headers:           %u (bytes)\n"            , ehdr->e_shentsize);
    printf("  Number of section headers:         %u\n"                    , ehdr->e_shnum);
    printf("  Section header string table index: %u\n"                    , ehdr->e_shstrndx);
}

static const char *get_section_type_name(unsigned int sh_type)
{
    switch (sh_type) {
        case SHT_NULL:          return "NULL";
        case SHT_PROGBITS:      return "PROGBITS";
        case SHT_SYMTAB:        return "SYMTAB";
        case SHT_STRTAB:        return "STRTAB";
        case SHT_RELA:          return "RELA";
        case SHT_HASH:          return "HASH";
        case SHT_DYNAMIC:       return "DYNAMIC";
        case SHT_NOTE:          return "NOTE";
        case SHT_NOBITS:        return "NOBITS";
        case SHT_REL:           return "REL";
        case SHT_SHLIB:         return "SHLIB";
        case SHT_DYNSYM:        return "DYNSYM";
        case SHT_INIT_ARRAY:    return "INIT_ARRAY";
        case SHT_FINI_ARRAY:    return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case SHT_GNU_HASH:      return "GNU_HASH";
        case SHT_GROUP:         return "GROUP";
        case SHT_SYMTAB_SHNDX:  return "SYMTAB SECTION INDICES";
        case SHT_GNU_verdef:    return "VERDEF";
        case SHT_GNU_verneed:   return "VERNEED";
        case SHT_GNU_versym:    return "VERSYM";
        case 0x6ffffff0:        return "VERSYM";
        case 0x6ffffffc:        return "VERDEF";
        case 0x7ffffffd:        return "AUXILIARY";
        case 0x7fffffff:        return "FILTER";
        case SHT_GNU_LIBLIST:   return "GNU_LIBLIST";
        default:                return "not support";
    }
}

static const char *get_section_flag_symbols(unsigned long long int sh_flags)
{
    switch (sh_flags&7) { /* only support WAX */
        case 0:                         return    "";
        case SHF_WRITE:                 return   "W";
        case SHF_ALLOC:                 return   "A";
        case SHF_ALLOC | SHF_WRITE:     return  "WA";
        case SHF_EXECINSTR:             return   "X";
        case SHF_EXECINSTR | SHF_WRITE: return  "WX";
        case SHF_EXECINSTR | SHF_ALLOC: return  "AX";
        default:                        return "WAX";
   }
}

void process_section_header()
{
    printf("\nSection Headers:\n");
    printf("  [Nr] Name              Type             Address           Offset\n");
    printf("       Size              EntSize          Flags  Link  Info  Align\n");
    
    for (i = 0; i < ehdr->e_shnum; i++) {
        printf("  [%2d] %-17.17s %-16s %016lx  %08lx\n", i, shdr[i].sh_name+sh_strtab_p, get_section_type_name(shdr[i].sh_type), shdr[i].sh_addr, shdr[i].sh_offset);
        printf("       %016lx  %016lx %3s    %4d  %4d     %-4ld\n", shdr[i].sh_size, shdr[i].sh_entsize, get_section_flag_symbols(shdr[i].sh_flags), \
                                                                    shdr[i].sh_link, shdr[i].sh_info, shdr[i].sh_addralign);
    }

    printf("Key to Flags:\n"
           "  W (write), A (alloc), X (execute)\n");
}

static const char *get_segment_type(unsigned long p_type)
{
    switch (p_type) {
        case PT_NULL:              return "NULL";
        case PT_LOAD:              return "LOAD";
        case PT_DYNAMIC:           return "DYNAMIC";
        case PT_INTERP:            return "INTERP";
        case PT_NOTE:              return "NOTE";
        case PT_SHLIB:             return "SHLIB";
        case PT_PHDR:              return "PHDR";
        case PT_TLS:               return "TLS";
        case PT_GNU_EH_FRAME:      return "GNU_EH_FRAME";
        case PT_GNU_STACK:         return "GNU_STACK";
        case PT_GNU_RELRO:         return "GNU_RELRO";
        default:                   return "not support";
    }
}

void process_program_header()
{
    printf("\nProgram Headers:\n");
    printf("  Type           Offset             VirtAddr           PhysAddr\n"
           "                 FileSiz            MemSiz              Flags  Align\n");
    
    for (i = 0; i < ehdr->e_phnum; i++) {
        printf("  %-14.14s "   , get_segment_type(phdr[i].p_type));
        printf("0x%16.16lx "   , phdr[i].p_offset);
        printf("0x%16.16lx "   , phdr[i].p_vaddr);
        printf("0x%16.16lx \n" , phdr[i].p_paddr);
        printf(" %16s", "");
        printf("0x%16.16lx "   , phdr[i].p_filesz);
        printf("0x%16.16lx "   , phdr[i].p_memsz);
        printf(" %c%c%c    "   , phdr[i].p_flags & PF_R ? 'R' : ' '
                               , phdr[i].p_flags & PF_W ? 'W' : ' '
                               , phdr[i].p_flags & PF_X ? 'E' : ' ');
        printf("0x%lx "        , phdr[i].p_align);
        putc('\n', stdout);
    }

    printf("\n Section to Segment mapping:\n");
    printf("  Segment Sections...\n");

    for (i = 0; i < ehdr->e_phnum; i++) {
        printf("   %2.2d     ", i);
        for (j = 0; j < ehdr->e_shnum; j++) {
            /* I'm not sure, it may be wrong ... :( */
            if (shdr[j].sh_offset >= phdr[i].p_offset && 
                shdr[j].sh_offset + shdr[j].sh_size <= phdr[i].p_offset + phdr[i].p_memsz &&
                shdr[j].sh_addr)
                printf("%s ", shdr[j].sh_name + sh_strtab_p);
        }

        putc('\n', stdout);
    }
}

static const char *get_dynamic_type(unsigned long type)
{
    switch (type) {
        case DT_NULL:            return "(NULL)";
        case DT_NEEDED:          return "(NEEDED)";
        case DT_PLTRELSZ:        return "(PLTRELSZ)";
        case DT_PLTGOT:          return "(PLTGOT)";
        case DT_HASH:            return "(HASH)";
        case DT_STRTAB:          return "(STRTAB)";
        case DT_SYMTAB:          return "(SYMTAB)";
        case DT_RELA:            return "(RELA)";
        case DT_RELASZ:          return "(RELASZ)";
        case DT_RELAENT:         return "(RELAENT)";
        case DT_STRSZ:           return "(STRSZ)";
        case DT_SYMENT:          return "(SYMENT)";
        case DT_INIT:            return "(INIT)";
        case DT_FINI:            return "(FINI)";
        case DT_SONAME:          return "(SONAME)";
        case DT_RPATH:           return "(RPATH)";
        case DT_SYMBOLIC:        return "(SYMBOLIC)";
        case DT_REL:             return "(REL)";
        case DT_RELSZ:           return "(RELSZ)";
        case DT_RELENT:          return "(RELENT)";
        case DT_PLTREL:          return "(PLTREL)";
        case DT_DEBUG:           return "(DEBUG)";
        case DT_TEXTREL:         return "(TEXTREL)";
        case DT_JMPREL:          return "(JMPREL)";
        case DT_BIND_NOW:        return "(BIND_NOW)";
        case DT_INIT_ARRAY:      return "(INIT_ARRAY)";
        case DT_FINI_ARRAY:      return "(FINI_ARRAY)";
        case DT_INIT_ARRAYSZ:    return "(INIT_ARRAYSZ)";
        case DT_FINI_ARRAYSZ:    return "(FINI_ARRAYSZ)";
        case DT_RUNPATH:         return "(RUNPATH)";
        case DT_FLAGS:           return "(FLAGS)";
        case DT_PREINIT_ARRAY:   return "(PREINIT_ARRAY)";
        case DT_PREINIT_ARRAYSZ: return "(PREINIT_ARRAYSZ)";
        case DT_SYMTAB_SHNDX:    return "(SYMTAB_SHNDX)";
        case DT_CHECKSUM:        return "(CHECKSUM)";
        case DT_PLTPADSZ:        return "(PLTPADSZ)";
        case DT_MOVEENT:         return "(MOVEENT)";
        case DT_MOVESZ:          return "(MOVESZ)";
        case DT_POSFLAG_1:       return "(POSFLAG_1)";
        case DT_SYMINSZ:         return "(SYMINSZ)";
        case DT_SYMINENT:        return "(SYMINENT)";   
        case DT_ADDRRNGLO:       return "(ADDRRNGLO)";
        case DT_CONFIG:          return "(CONFIG)";
        case DT_DEPAUDIT:        return "(DEPAUDIT)";
        case DT_AUDIT:           return "(AUDIT)";
        case DT_PLTPAD:          return "(PLTPAD)";
        case DT_MOVETAB:         return "(MOVETAB)";
        case DT_SYMINFO:         return "(SYMINFO)";
        case DT_VERSYM:          return "(VERSYM)";
        case DT_TLSDESC_GOT:     return "(TLSDESC_GOT)";
        case DT_TLSDESC_PLT:     return "(TLSDESC_PLT)";
        case DT_RELACOUNT:       return "(RELACOUNT)";
        case DT_RELCOUNT:        return "(RELCOUNT)";
        case DT_FLAGS_1:         return "(FLAGS_1)";
        case DT_VERDEF:          return "(VERDEF)";
        case DT_VERDEFNUM:       return "(VERDEFNUM)";
        case DT_VERNEED:         return "(VERNEED)";
        case DT_VERNEEDNUM:      return "(VERNEEDNUM)";
        case DT_AUXILIARY:       return "(AUXILIARY)";
        case DT_FILTER:          return "(FILTER)";
        default:                 return "(not support)";
    }
}

void print_dynamic_flags(unsigned int flag)
{
    switch (flag){
        case DF_ORIGIN:     fputs("ORIGIN", stdout); break;
        case DF_SYMBOLIC:   fputs("SYMBOLIC", stdout); break;
        case DF_TEXTREL:    fputs("TEXTREL", stdout); break;
        case DF_BIND_NOW:   fputs("BIND_NOW", stdout); break;
        case DF_STATIC_TLS: fputs("STATIC_TLS", stdout); break;
        default:            fputs("unknown", stdout); break;
    }
}

void process_dynamic_section()
{
    Elf64_Dyn *entry;
    char *name;
    size_t dynamic_nent = 0;
    unsigned long int val; 

    entry = (Elf64_Dyn *)(file_addr + sh_dynamic->sh_offset);
    for (; (void *)&entry[dynamic_nent] < (void *)(file_addr + sh_dynamic->sh_offset + sh_dynamic->sh_size); dynamic_nent++)
        if (!entry[dynamic_nent].d_tag)
            break;

    dynamic_nent ++;

    printf("\nDynamic section at offset 0x%lx contains %lu entry:\n", sh_dynamic->sh_offset, dynamic_nent);
    printf("  Tag        Type                         Name/Value\n");

    for (i = 0; i < dynamic_nent; i++) {
        printf(" 0x%16.16lx %-21s", entry[i].d_tag, get_dynamic_type(entry[i].d_tag));

        val = entry[i].d_un.d_val;
        name = sh_dynstr_p + val;

        switch (entry[i].d_tag) {
            case DT_NEEDED:
                printf("Shared library: [%s]", name);
                break;

            case DT_SONAME:
                printf("Library soname: [%s]", name);
                break;

            case DT_RPATH:
                printf("Library rpath: [%s]", name);
                break;

            case DT_RUNPATH:
                printf("Library runpath: [%s]", name);
                break;
            
            case DT_INIT_ARRAYSZ:
            case DT_FINI_ARRAYSZ:
            case DT_STRSZ:
            case DT_SYMENT:
            case DT_PLTRELSZ:
            case DT_RELASZ:
            case DT_RELAENT:
                printf("%ld (bytes)", val);
                break;

            case DT_FLAGS:
                print_dynamic_flags(val);
                break;

            case DT_FLAGS_1:
                 printf("FLAGs: ");
                 if (val & DF_1_NOW) {
                     printf("NOW ");
                     val ^= DF_1_NOW;
                 }
                 if (val & DF_1_GLOBAL) {
                     printf("GLOBAL ");
                      val ^= DF_1_GLOBAL;
                 }
                 if (val & DF_1_GROUP) {
                     printf("GROUP ");
                     val ^= DF_1_GROUP;
                 }
                 if (val & DF_1_NODELETE) {
                     printf("NODELETE ");
                     val ^= DF_1_NODELETE;
                 }
                 if (val & DF_1_LOADFLTR){
                     printf("LOADFLTR ");
                     val ^= DF_1_LOADFLTR;
                 }
                 if (val & DF_1_INITFIRST) {
                 
                     printf("INITFIRST ");
                     val ^= DF_1_INITFIRST;
                 }
                 if (val & DF_1_NOOPEN) {
                     printf("NOOPEN ");
                     val ^= DF_1_NOOPEN;
                 }
                 if (val & DF_1_ORIGIN) {
                     printf("ORIGIN ");
                     val ^= DF_1_ORIGIN;
                 } 
                 if (val & DF_1_DIRECT) {
                     printf("DIRECT ");
                     val ^= DF_1_DIRECT;
                 }
                 if (val & DF_1_TRANS) {
                     printf("TRANS ");
                     val ^= DF_1_TRANS;
                 }
                 if (val & DF_1_INTERPOSE) {
                     printf("INTERPOSE ");
                     val ^= DF_1_INTERPOSE;
                 }
                 if (val & DF_1_NODEFLIB) {
                     printf("NODEFLIB ");
                     val ^= DF_1_NODEFLIB;
                 }
                 if (val & DF_1_NODUMP) {
                     printf("NODUMP ");
                     val ^= DF_1_NODUMP;
                 }
                 if (val & DF_1_CONFALT) {
                     printf("CONFALT ");
                     val ^= DF_1_CONFALT;
                 }
                 if (val & DF_1_ENDFILTEE) {
                     printf("ENDFILTEE ");
                     val ^= DF_1_ENDFILTEE;
                 }
                 if (val & DF_1_DISPRELDNE) {
                     printf("DISPRELDNE ");
                     val ^= DF_1_DISPRELDNE;
                 }
                 if (val & DF_1_DISPRELPND) {
                     printf("DISPRELPND ");
                     val ^= DF_1_DISPRELPND;
                 }
                 if (val & DF_1_NODIRECT) {
                     printf("NODIRECT ");
                     val ^= DF_1_NODIRECT;
                 }
                 if (val & DF_1_IGNMULDEF) {
                     printf("IGNMULDEF ");
                     val ^= DF_1_IGNMULDEF;
                 }
                 if (val & DF_1_NOKSYMS) {
                     printf("NOKSYMS ");
                     val ^= DF_1_NOKSYMS;
                 }
                 if (val & DF_1_NOHDR) {
                     printf("NOHDR ");
                     val ^= DF_1_NOHDR;
                 }
                 if (val & DF_1_EDITED) {
                     printf("EDITED ");
                     val ^= DF_1_EDITED;
                 }
                 if (val & DF_1_NORELOC) {
                     printf("NORELOC ");
                     val ^= DF_1_NORELOC;
                 }
                 if (val & DF_1_SYMINTPOSE) {
                     printf("SYMINTPOSE ");
                     val ^= DF_1_SYMINTPOSE;
                 }
                 if (val & DF_1_GLOBAUDIT) {
                     printf("GLOBAUDIT ");
                     val ^= DF_1_GLOBAUDIT;
                 }
                 if (val & DF_1_SINGLETON) {
                     printf("SINGLETON ");
                     val ^= DF_1_SINGLETON;
                 }
                 if (val & DF_1_STUB) {
                     printf("STUB ");
                     val ^= DF_1_STUB;
                 }
                 if (val & DF_1_PIE) {
                     printf("PIE ");
                     val ^= DF_1_PIE;
                 }
                 if (val & DF_1_KMOD) {
                     printf("KMOD ");
                     val ^= DF_1_KMOD;
                 }
                 if (val & DF_1_WEAKFILTER) {
                     printf("WEAKFILTER ");
                     val ^= DF_1_WEAKFILTER;
                 }
                 if (val & DF_1_NOCOMMON) {
                     printf("NOCOMMON ");
                     val ^= DF_1_NOCOMMON;
                 }
                 if (val != 0) {
                   printf("%lx", val);
                 }
                 break;

            case DT_VERNEEDNUM:
            case DT_RELACOUNT:
                 printf("%ld", val);
                 break;

            case DT_PLTREL:
                printf("%s", get_dynamic_type(val));
                break;

            default:
                printf("0x%lx", entry[i].d_un.d_val);
              
        }
        putc('\n', stdout);
    }
}



static const char *get_rela_type(unsigned int type)
{
    switch (type) {
        case R_X86_64_NONE:      return "R_X86_64_NONE"; 
        case R_X86_64_64:        return "R_X86_64_64";      
        case R_X86_64_PC32:      return "R_X86_64_PC32";  
        case R_X86_64_GOT32:     return "R_X86_64_GOT32";         
        case R_X86_64_PLT32:     return "R_X86_64_PLT32";       
        case R_X86_64_COPY:      return "R_X86_64_COPY";         
        case R_X86_64_GLOB_DAT:  return "R_X86_64_GLOB_DAT";        
        case R_X86_64_JUMP_SLOT: return "R_X86_64_JUMP_SLOT";
        case R_X86_64_RELATIVE:  return "R_X86_64_RELATIVE";   
        case R_X86_64_GOTPCREL:  return "R_X86_64_GOTPCREL";   
        case R_X86_64_32:        return "R_X86_64_32";    
        case R_X86_64_32S:       return "R_X86_64_32S";      
        case R_X86_64_16:        return "R_X86_64_16";    
        case R_X86_64_PC16:      return "R_X86_64_PC16";     
        case R_X86_64_8:         return "R_X86_64_8";       
        case R_X86_64_PC8:       return "R_X86_64_PC8";          
        case R_X86_64_PC64:      return "R_X86_64_PC64";         
        default:                 return "not support";
    }
}

void process_relocs()
{
    Elf64_Rela *rela_entry;
    Elf64_Sym  *sym_entry, *psym;
    Elf64_Vernaux *vernaux;
    uint64_t rel_size, rel_offset, num_rela;
    uint32_t type, dynsymtab_idx;
    uint16_t vers_data;
    const char *name, *version_str;

    sym_entry = (Elf64_Sym *)(file_addr + sh_dynsym->sh_offset);
    vernaux   = (Elf64_Vernaux *)(file_addr + sh_gnu_version_r->sh_offset);

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type != SHT_RELA && shdr[i].sh_type != SHT_REL)
            continue;
        
        rel_offset = shdr[i].sh_offset;
        rel_size   = shdr[i].sh_size;
        num_rela   = rel_size / shdr[i].sh_entsize;

        if (rel_size) {
            printf("\nRelocation section ");
            printf("'%s' at offset 0x%lx contains %lu entries:\n", sh_strtab_p + shdr[i].sh_name, rel_offset, num_rela);
            printf("  Offset          Info           Type           Sym. Value    Sym. Name + Addend\n");
        }
        
        if (shdr[i].sh_type == SHT_RELA) {
            rela_entry = (Elf64_Rela *)(file_addr + shdr[i].sh_offset);
            for (j = 0; j < num_rela; j++) {
                type          = rela_entry[j].r_info&0xffffffff;
                dynsymtab_idx = rela_entry[j].r_info>>32;
                psym          = sym_entry + dynsymtab_idx;
                name          = sh_dynstr_p + psym->st_name;
                vers_data = *(unsigned short *)(file_addr + sh_gnu_version->sh_offset + dynsymtab_idx * sizeof(vers_data));

                printf("%012lx  "  , rela_entry[j].r_offset);
                printf("%012lx "   , rela_entry[j].r_info);
                printf("%-17.17s " , get_rela_type(type));

                version_str = NULL;
                if (vers_data) {
                    k = 0;
                    do {
                        k++;
                    } while (vernaux[k].vna_other != vers_data && vernaux[k].vna_next);
                    version_str = sh_dynstr_p + vernaux[k].vna_name;
                }

                switch (type) {
                    case R_X86_64_RELATIVE:
                        printf("%16s   %lx", "", rela_entry[j].r_addend);
                        break;

                    case R_X86_64_COPY:
                        printf("%016lx  %s", rela_entry[j].r_offset, name);
                        if (version_str)
                            printf("@%s",  version_str);
                        printf(" + %ld", rela_entry[j].r_addend);
                        break;

                    default:
                        printf("%016lx  %s", rela_entry[j].r_addend, name);
                        if (version_str)
                            printf("@%s",  version_str);
                        printf(" + %ld", rela_entry[j].r_addend);
                }

                putc('\n', stdout);
            }
        }
    }
}

static const char *get_symbol_type(unsigned int type)
{
    switch (type) {
        case STT_NOTYPE:  return "NOTYPE";
        case STT_OBJECT:  return "OBJECT";
        case STT_FUNC:    return "FUNC";
        case STT_SECTION: return "SECTION";
        case STT_FILE:    return "FILE";
        case STT_COMMON:  return "COMMON";
        case STT_TLS:     return "TLS";
        default:          return "not support";
    }
}

static const char *get_symbol_binding(unsigned int binding)
{
    switch (binding) {
        case STB_LOCAL:  return "LOCAL";
        case STB_GLOBAL: return "GLOBAL";
        case STB_WEAK:   return "WEAK";
        default:         return "not support";
    }
}

static const char *get_symbol_visibility(unsigned int visibility)
{
    switch (visibility)
    {
        case STV_DEFAULT:   return "DEFAULT";
        case STV_INTERNAL:  return "INTERNAL";
        case STV_HIDDEN:    return "HIDDEN";
        case STV_PROTECTED: return "PROTECTED";
        default:            return "not support";
    }
}

static const char *get_symbol_index_type(unsigned int type)
{
    static char buf[32];
    switch (type) {
        case SHN_UNDEF:  return "UND";
        case SHN_ABS:    return "ABS";
        case SHN_COMMON: return "COM";
        default:
            sprintf(buf, "%3d", type);
    }
    return buf;
}

void process_symbol_table()
{
    Elf64_Shdr *string_sec;
    Elf64_Sym *psym;
    Elf64_Rela *rela_entry;
    char *gnu_hash;
    uint16_t  vers_data;
    int32_t ngnubuckets, gnusymidx, bitmaskwords;
    int32_t *gnubuckets, *gnuchains, *lengths, *counts;
    int32_t num_syms, num_dynsyms, chain_length, nzero_counts, length, maxlength = 0;

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type != SHT_SYMTAB && shdr[i].sh_type != SHT_DYNSYM)
            continue;
        if (shdr[i].sh_entsize == 0) {
            printf("\nSymbol table '%s' has a sh_entsize of zero!\n", sh_strtab_p + shdr[i].sh_name);
            continue;
        }

        num_syms = shdr[i].sh_size / shdr[i].sh_entsize;
        printf("\nSymbol table '%s' contains %u entry:\n", sh_strtab_p + shdr[i].sh_name, num_syms);
        printf ("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n");

        string_sec = &shdr[shdr[i].sh_link];
        psym = (Elf64_Sym *)(file_addr + shdr[i].sh_offset);
        for (j = 0; j < num_syms; j++) {
            vers_data = *(int32_t *)(file_addr + sh_gnu_version->sh_offset + j*sizeof(vers_data));

            printf("%6d: "   , j);
            printf("%016lx " , psym[j].st_value);
            printf("%5ld "   , psym[j].st_size);
            printf("%-7s "   , get_symbol_type(psym[j].st_info&0xf));
            printf("%-6s "   , get_symbol_binding(psym[j].st_info>>4));
            printf("%-7s "   , get_symbol_visibility(psym[j].st_other));
            printf("%4s "    , get_symbol_index_type(psym[j].st_shndx));
            printf("%s "     , file_addr + string_sec->sh_offset + psym[j].st_name);

            if (vers_data && shdr[i].sh_type == SHT_DYNSYM) {
                printf("(%d)", vers_data);
                num_dynsyms = num_syms;
            }

            putc('\n', stdout);
        }
    }

    gnu_hash     = file_addr + sh_gnu_hash->sh_offset;
    ngnubuckets  = *(int32_t *)gnu_hash;
    gnusymidx    = *(int32_t  *)(gnu_hash + sizeof(ngnubuckets));
    bitmaskwords = *(int32_t *)(gnu_hash + sizeof(ngnubuckets) + sizeof(gnusymidx));
    chain_length = num_dynsyms - gnusymidx;
    gnubuckets   = (int32_t *)calloc(ngnubuckets , sizeof(int32_t));
    gnuchains    = (int32_t *)calloc(chain_length, sizeof(int32_t));
    lengths      = (int32_t *)calloc(ngnubuckets , sizeof(int32_t));

    for (i = 0; i < ngnubuckets; i++)
        gnubuckets[i] = *(int32_t *)(gnu_hash + 0x18 + i*sizeof(int32_t));
    
    for (i = 0; i < chain_length; i++) 
        gnuchains[i] = *(int32_t *)(gnu_hash + 0x18 + (ngnubuckets + i)*sizeof(int32_t));

    for (i = 0; i < ngnubuckets; i++) {
        length = 0;
        for (unsigned int j = gnubuckets[i] - gnusymidx; j < chain_length; j++) {
            length++;
            if (gnuchains[j]&1)
                break;
        }
        lengths[i] = length;
        if (length > maxlength)
            maxlength = length;
    }

    counts = (int32_t *)calloc(maxlength+1, sizeof(int32_t));
    for (i = 0; i < ngnubuckets; i++)
        counts[lengths[i]]++;

    printf("\nHistogram for `%s' bucket list length total of %u bucket):\n", ".gnu.hash", ngnubuckets);
    printf(" Length  Number     %% of total  Coverage\n");
    printf("      0  %-10u (%5.1f%%)\n", counts[0], (counts[0] * 100.0) / ngnubuckets);

    for (i = 1, nzero_counts = 0; i <= maxlength; i++) {
        nzero_counts += i * counts[i];
        printf("%7u  %-10u (%5.1f%%)    %5.1f%%\n", i, counts[i], (counts[i] * 100.0) / ngnubuckets, (nzero_counts * 100.0) / chain_length);
    }

    free(gnubuckets);
    free(gnuchains);
    free(lengths);
    free(counts);
}

static const char *get_ver_flags(unsigned int flags)
{
    static char buff[128];

    buff[0] = 0;
    if (flags == 0)
        return "none";

    if (flags & VER_FLG_BASE)
        strcat (buff, "BASE");

    if (flags & VER_FLG_WEAK) {
        if (flags & VER_FLG_BASE)
            strcat (buff, " | ");
        strcat (buff, "WEAK");
    }

    return buff; 
}

void process_version_sections()
{
    Elf64_Rela *rela_entry;
    Elf64_Vernaux *vernaux;
    Elf64_Verneed *verneed;
    size_t total, idx, isum;
    int16_t *data;
    const char *version_str;

    vernaux = (Elf64_Vernaux *)(file_addr + sh_gnu_version_r->sh_offset);

    for (i = 0; i < ehdr->e_shnum; i++) {
        switch (shdr[i].sh_type) {
        case SHT_GNU_verdef:
            printf("not support\n");
            break;

        case SHT_GNU_verneed:
            printf("\nVersion needs section '%s' contains %u entry:\n", sh_strtab_p+shdr[i].sh_name, shdr[i].sh_info);
            printf(" Addr: 0x%016lx  Offset: %#08lx  Link: %u (%s)\n" , shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_link, shdr[shdr[i].sh_link].sh_name+sh_strtab_p);

            for (j = idx = 0; j < shdr[i].sh_info; j++) {
                verneed = (Elf64_Verneed *)(file_addr + shdr[i].sh_offset) + idx;

                printf("  %#06x: Version: %d", j, verneed->vn_version);
                printf("  File: %s", sh_dynstr_p + verneed->vn_file);
                printf("  Cnt: %d\n", verneed->vn_cnt);

                for (k = 0, isum = idx + verneed->vn_aux; k < verneed->vn_cnt; k++) {
                    vernaux = (Elf64_Vernaux *)((void *)verneed + verneed->vn_aux) + k;
                    printf("  %#06lx:   Name: %s", isum, sh_dynstr_p + vernaux->vna_name);
                    printf("  Flags: %s  Version: %d\n", get_ver_flags(vernaux->vna_flags), vernaux->vna_other);
                    isum += vernaux->vna_next;
                }

                idx  += verneed->vn_next;
            }
            break;

        case SHT_GNU_versym:
            total = shdr[i].sh_size / sizeof(Elf64_Half);
            printf("\nVersion symbols section '%s' contains %lu entry:\n", sh_strtab_p+shdr[i].sh_name, total);
            printf(" Addr: 0x%016lx  Offset: %#08lx  Link: %u (%s)\n", shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_link, shdr[shdr[i].sh_link].sh_name+sh_strtab_p);

            data = (int16_t *)(file_addr + shdr[i].sh_offset);
            for (j = 0; j < total; j += 4) {
                printf("  %03x:", j);

                for (k = 0; k<4 && j+k < total; k++) {
                    switch (data[j+k]) {
                    case 0:
                        fputs("   0 (*local*)    ", stdout);
                        break;
                   
                    case 1:
                        fputs("   1 (*global*)   ", stdout);
                        break;

                    default:
                        l = 0;
                        do {
                            l++;
                        } while (vernaux[l].vna_other != data[j+k] && vernaux[l].vna_next);

                        version_str = sh_dynstr_p + vernaux[l].vna_name;
                        printf("   %d (%s%-*s", data[j+k], version_str, 12 - (int)strlen(version_str), ")");
                        break;
                    }
                }

                putc('\n', stdout);
            }
            break;

        default:
            break;
        }
    }
}

static const char *get_gnu_elf_note_type (unsigned e_type)
{
    switch (e_type) {
    case NT_GNU_ABI_TAG:
        return "NT_GNU_ABI_TAG (ABI version tag)";
    case NT_GNU_HWCAP:
        return "NT_GNU_HWCAP (DSO-supplied software HWCAP info)";
    case NT_GNU_BUILD_ID:
        return "NT_GNU_BUILD_ID (unique build ID bitstring)";
    case NT_GNU_GOLD_VERSION:
        return "NT_GNU_GOLD_VERSION (gold version)";
    case NT_GNU_PROPERTY_TYPE_0:
        return "NT_GNU_PROPERTY_TYPE_0";
    default:
        return "unknown";
    }
}

static void decode_x86_feature_1(unsigned int bitmask)
{
    if (!bitmask) {
        printf("None");
        return;
    }

    while (bitmask) {

        unsigned int bit = bitmask & (-bitmask);
        bitmask &= ~bit;

        switch (bit) {
        case GNU_PROPERTY_X86_FEATURE_1_IBT:
            printf("IBT");
            break;

        case GNU_PROPERTY_X86_FEATURE_1_SHSTK:
            printf("SHSTK");
            break;
    
        default:
            printf("unknown: %x", bit);
            break;
        }

        if (bitmask)
           printf(", ");
    }
}

void process_note_section()
{
    Elf64_Nhdr *note;
    char *name, *descdata;
    int32_t type, datasz, bitmask;
    int32_t os, major, minor, subminor;
    const char *osname;

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_NOTE) {
            printf("\nDisplaying notes found in: %s\n", sh_strtab_p + shdr[i].sh_name);
            printf("  %-20s %-10s\tDescription\n", "Owner", "Data size");

            note = (Elf64_Nhdr *)(file_addr + shdr[i].sh_offset);
            name = (void *)note+sizeof(Elf64_Nhdr);
            descdata = name + note->n_namesz;

            if (note->n_namesz)
                printf("  %s", name);
            else
                printf("  (NONE)");

            printf("                  %#08x", note->n_descsz);
            printf("         %s\n", get_gnu_elf_note_type(note->n_type));

            switch (note->n_type) {
            case NT_GNU_BUILD_ID:
                printf("    Build ID: ");
                for (j = 0; j < note->n_descsz; ++j)
                    printf("%02x", descdata[j] & 0xff);
                printf("\n");
                break;

            case NT_GNU_ABI_TAG:
                os       = *(int32_t *)(descdata);
                major    = *(int32_t *)(descdata+4);
                minor    = *(int32_t *)(descdata+8);
                subminor = *(int32_t *)(descdata+12);

                switch (os) {
                case 0:
                    osname = "Linux";
                    break;
                default:
                    osname = "not support";
                }

                printf("    OS: %s, ABI: %d.%d.%d\n", osname, major, minor, subminor);
                break;

            case NT_GNU_GOLD_VERSION:
            case NT_GNU_HWCAP:
                break;

            case NT_GNU_PROPERTY_TYPE_0:
                printf("      Properties: ");

                type   = *(int32_t *)descdata;
                datasz = *(int32_t *)(descdata+4);
                bitmask = *(int32_t *)(descdata+8);

                switch (type) {
                case GNU_PROPERTY_X86_FEATURE_1_AND:
                    printf("x86 feature: ");
                    decode_x86_feature_1(bitmask);
                    break;

                default:
                    printf("not support");
                }
                break;

            default:
                printf("    Description data: ");
                for (j = 0; j < note->n_descsz; j++)
                    printf("%02x ", descdata[j]&0xff);
                printf("\n");
            }

            putc('\n', stdout);
        }
    }
}

void init(char *filename)
{
    int fd = -1;
    struct stat statbuf;

    if (stat(filename, &statbuf) < 0) {
        printf("%s not existed\n", filename);
        goto fail;
    }

    if (!S_ISREG(statbuf.st_mode)) {
        printf("file is not a regular file\n");
        goto fail;
    }
    
    fd = open(filename, O_RDONLY);
    file_addr = mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    
    ehdr = (Elf64_Ehdr *)file_addr;
    shdr = (Elf64_Shdr *)(file_addr + ehdr->e_shoff);
    phdr = (Elf64_Phdr *)(file_addr + ehdr->e_phoff);
    sh_strtab = &shdr[ehdr->e_shstrndx];
    sh_strtab_p = file_addr + sh_strtab->sh_offset;

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (!strcmp(shdr[i].sh_name + sh_strtab_p, ".dynamic"))
            sh_dynamic = &shdr[i];
        if (!strcmp(shdr[i].sh_name + sh_strtab_p, ".dynstr"))
            sh_dynstr = &shdr[i];
        if (!strcmp(shdr[i].sh_name + sh_strtab_p, ".dynsym"))
            sh_dynsym = &shdr[i];
        if (!strcmp(shdr[i].sh_name + sh_strtab_p, ".gnu.version"))
            sh_gnu_version = &shdr[i];
        if (!strcmp(shdr[i].sh_name + sh_strtab_p, ".gnu.version_r"))
            sh_gnu_version_r = &shdr[i];
        if (!strcmp(shdr[i].sh_name + sh_strtab_p, ".gnu.hash"))
            sh_gnu_hash = &shdr[i];
    }

    sh_dynstr_p = file_addr + sh_dynstr->sh_offset;

    return;

fail:
    exit(-1);
}

int main(int argc, char **argv)
{

    char filename[MAX_FILENAME_SIZE];

    if (argc < 2)
        usage(argv);

    strncpy(filename, argv[1], sizeof(filename));

    init(filename);
    process_file_header();
    process_section_header();
    process_program_header();
    process_dynamic_section();
    process_relocs();
    process_symbol_table();
    process_version_sections();
    process_note_section();

    return 0;
}
