#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include "Windows.h"

char *file_addr;
PIMAGE_DOS_HEADER dos_hdr;
PIMAGE_NT_HEADERS nt_hdr;
PIMAGE_SECTION_HEADER section_hdr;
int i, j, k;

void init(const LPCSTR filename)
{
	HANDLE hExecutable = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hExecutableMapping = CreateFileMapping(hExecutable, NULL, PAGE_READONLY, 0, 0, NULL);

	file_addr   = MapViewOfFile(hExecutableMapping, FILE_MAP_READ, 0, 0, 0);
	dos_hdr     = (PIMAGE_DOS_HEADER)file_addr;
	nt_hdr      = (PIMAGE_NT_HEADERS)((BYTE *)dos_hdr + dos_hdr->e_lfanew);
	section_hdr = IMAGE_FIRST_SECTION(nt_hdr);
}

void parse_dos_header()
{
	printf("---------------------- dos header -----------------------------------\n");
	printf("Magic number                             : %lX\n", dos_hdr->e_magic);
	printf("Bytes on last page of file               : %lX\n", dos_hdr->e_cblp);
	printf("Page in file                             : %lX\n", dos_hdr->e_cp);
	printf("Relocations                              : %lX\n", dos_hdr->e_crlc);
	printf("Size of header in paragraphs             : %lX\n", dos_hdr->e_cparhdr);
	printf("Minimum extra paragraphs needed          : %lX\n", dos_hdr->e_minalloc);
	printf("Maximum extra paragraphs needed          : %lX\n", dos_hdr->e_maxalloc);
	printf("Initial (relative) SS value              : %lX\n", dos_hdr->e_ss);
	printf("Initial SP value                         : %lX\n", dos_hdr->e_sp);
	printf("Checksum                                 : %lX\n", dos_hdr->e_csum);
	printf("Initial IP value                         : %lX\n", dos_hdr->e_ip);
	printf("Initial (relative) CS value              : %lX\n", dos_hdr->e_cs);
	printf("File address of relocation table         : %lX\n", dos_hdr->e_lfarlc);
	printf("Overlay number                           : %lX\n", dos_hdr->e_ovno);
	printf("Reserved words[4]                        : %lX, %lX, %lX, %lX\n", dos_hdr->e_res[0], dos_hdr->e_res[1], dos_hdr->e_res[2], dos_hdr->e_res[3]);
	printf("OEM identifier (for OEM information)     : %lX\n", dos_hdr->e_oemid);
	printf("OEM information; OEM identifier specific : %lX\n", dos_hdr->e_oeminfo);
	printf("Reserved words[10]                       : ");

	for (i = 0; i < 10; i++)
		printf("%d, ", dos_hdr->e_res2[i]);

	putc('\n', stdout);
	printf("File address of new exe header           : %lX\n", dos_hdr->e_lfanew);
}

static const char* get_FileHeader_machine(UINT16 machine)
{
	switch (machine) {
	case IMAGE_FILE_MACHINE_I386:  return "Intel 386";
	case IMAGE_FILE_MACHINE_IA64:  return "Intel 64";
	case IMAGE_FILE_MACHINE_AMD64: return "AMD64 (k8)";
	default:                       return "not support";
	}
}

void parse_FileHeader_Characteristic(UINT16 characteristic)
{
	if (characteristic & IMAGE_FILE_RELOCS_STRIPPED)
		printf("                         %-3lx        Relocation info stripped from file.\n", IMAGE_FILE_RELOCS_STRIPPED);
	if (characteristic & IMAGE_FILE_EXECUTABLE_IMAGE)
		printf("                         %-3lx        File is executable  (i.e. no unresolved external references).\n", IMAGE_FILE_EXECUTABLE_IMAGE);
	if (characteristic & IMAGE_FILE_LINE_NUMS_STRIPPED)
		printf("                         %-3lx        Line nunbers stripped from file.\n", IMAGE_FILE_LINE_NUMS_STRIPPED);
	if (characteristic & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
		printf("                         %-3lx        Local symbols stripped from file.\n", IMAGE_FILE_LOCAL_SYMS_STRIPPED);
	if (characteristic & IMAGE_FILE_AGGRESIVE_WS_TRIM)
		printf("                         %-3lx        Aggressively trim working set\n", IMAGE_FILE_AGGRESIVE_WS_TRIM);
	if (characteristic & IMAGE_FILE_LARGE_ADDRESS_AWARE)
		printf("                         %-3lx        App can handle >2gb addresses\n", IMAGE_FILE_LARGE_ADDRESS_AWARE);
	if (characteristic & IMAGE_FILE_BYTES_REVERSED_LO)
		printf("                         %-3lx        Bytes of machine word are reversed.\n", IMAGE_FILE_BYTES_REVERSED_LO);
	if (characteristic & IMAGE_FILE_32BIT_MACHINE)
		printf("                         %-3lx        32 bit word machine.\n", IMAGE_FILE_32BIT_MACHINE);
	if (characteristic & IMAGE_FILE_DEBUG_STRIPPED)
		printf("                         %-3lx        Debugging info stripped from file in .DBG file\n", IMAGE_FILE_DEBUG_STRIPPED);
	if (characteristic & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
		printf("                         %-3lx        If Image is on removable media, copy and run from the swap file.\n", IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP);
	if (characteristic & IMAGE_FILE_SYSTEM)
		printf("                         %-3lx        System File.\n", IMAGE_FILE_SYSTEM);
	if (characteristic & IMAGE_FILE_DLL)
		printf("                         %-3lx  File is a DLL.\n", IMAGE_FILE_DLL);
	if (characteristic & IMAGE_FILE_UP_SYSTEM_ONLY)
		printf("                         %-3lx   File should only be run on a UP machine.\n", IMAGE_FILE_UP_SYSTEM_ONLY);
	if (characteristic & IMAGE_FILE_BYTES_REVERSED_HI)
		printf("                         %-3lx  IBytes of machine word are reversed.\n", IMAGE_FILE_BYTES_REVERSED_HI);
}

static const char* get_OptionalHeader_Magic(UINT16 magic)
{
	switch (magic) {
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC: return "NT32";
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC: return "NT64";
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:  return "ROM";
	}
}

static const char* get_OptionalHeader_Subsystem(UINT16 subsystem)
{
	switch (subsystem) {
	case IMAGE_SUBSYSTEM_UNKNOWN:         return "Unknown subsystem";
	case IMAGE_SUBSYSTEM_NATIVE:          return "Driver";
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:     return "Windows GUI";
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:     return "Windows console";
	case IMAGE_SUBSYSTEM_OS2_CUI:         return "OS/2 console";
	case IMAGE_SUBSYSTEM_POSIX_CUI:       return "Posix console";
	case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:  return "Native Win9x driver";
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:  return "Windows CE subsystem";
	case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "WINDOWS_BOOT_APPLICATION";
	default:                              return "";
	}
}

void parse_OptionalHeader_DllCharacteristics(UINT16 characteristic)
{
	if (characteristic & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
		printf("                             %-4lx      Image can handle a high entropy 64-bit virtual address space.\n", IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		printf("                             %-4lx      DLL can move.\n", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
		printf("                             %-4lx      Code Integrity Image.\n", IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		printf("                             %-4lx      Image is NX compatible.\n", IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
		printf("                             %-4lx      Image understands isolation and doesn't want it.\n", IMAGE_DLLCHARACTERISTICS_NO_ISOLATION);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_NO_SEH)
		printf("                             %-4lx      Image does not use SEH.\n", IMAGE_DLLCHARACTERISTICS_NO_SEH);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_NO_BIND)
		printf("                             %-4lx      Do not bind this image.\n", IMAGE_DLLCHARACTERISTICS_NO_BIND);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
		printf("                             %-4lx      Image should execute in an AppContainer.\n", IMAGE_DLLCHARACTERISTICS_APPCONTAINER);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
		printf("                             %-4lx      Driver uses WDM model.\n", IMAGE_DLLCHARACTERISTICS_WDM_DRIVER);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
		printf("                             %-4lx      Image supports Control Flow Guard.\n", IMAGE_DLLCHARACTERISTICS_GUARD_CF);
	if (characteristic & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
		printf("                             %-4lx      TerminalServer aware.\n", IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE);
}

static const char* get_Data_Directory_Name(UINT32 idx)
{
	switch (idx) {
	case IMAGE_DIRECTORY_ENTRY_EXPORT:         return "Export Directory";
	case IMAGE_DIRECTORY_ENTRY_IMPORT:         return "Import Directory";
	case IMAGE_DIRECTORY_ENTRY_RESOURCE:       return "Resource Directory";
	case IMAGE_DIRECTORY_ENTRY_EXCEPTION:      return "Exception Directory";
	case IMAGE_DIRECTORY_ENTRY_SECURITY:       return "Security Directory";
	case IMAGE_DIRECTORY_ENTRY_BASERELOC:      return "Base Relocation Table";
	case IMAGE_DIRECTORY_ENTRY_DEBUG:          return "Debug Directory";
	case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:   return "Architecture Specific Data";
	//case IMAGE_DIRECTORY_ENTRY_COPYRIGHT:      return "???"; /*  (X86 usage) */
	case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:      return "RVA of GP";
	case IMAGE_DIRECTORY_ENTRY_TLS:            return "TLS Directory";
	case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:    return "Load Configuration Directory";
	case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:   return "Bound Import Directory in headers";
	case IMAGE_DIRECTORY_ENTRY_IAT:            return "Import Address Table";
	case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:   return "Delay Load Import Descriptors";
	case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: return "COM Runtime descriptor";
	default:                                   return "not support";
	}
}

void parse_nt_header()
{
	printf("\n---------------------- NT Headers -----------------------------------\n");
	printf("Signature : %lX\n", nt_hdr->Signature);
	printf("\n---------------------- File Header ----------------------------------\n");
	printf("Machine                : %lx    (%s)\n", nt_hdr->FileHeader.Machine, get_FileHeader_machine(nt_hdr->FileHeader.Machine));
	printf("Sections Count         : %lx\n", nt_hdr->FileHeader.NumberOfSections);
	printf("Time Date Stamp        : %d\n", nt_hdr->FileHeader.TimeDateStamp);
	printf("Ptr to Symbol Table    : %lx\n", nt_hdr->FileHeader.PointerToSymbolTable);
	printf("Num. of Symbols        : %lx\n", nt_hdr->FileHeader.NumberOfSymbols);
	printf("Size of OptionalHeader : %lx\n", nt_hdr->FileHeader.SizeOfOptionalHeader);
	printf("Characteristics        : %lx\n", nt_hdr->FileHeader.Characteristics);
	parse_FileHeader_Characteristic(nt_hdr->FileHeader.Characteristics);

	printf("\n---------------------- Optional Header ------------------------------\n");
	printf("Magic                      : %lX  (%s)\n", nt_hdr->OptionalHeader.Magic, get_OptionalHeader_Magic(nt_hdr->OptionalHeader.Magic));
	printf("Linker Ver. (Major)        : %lX\n", nt_hdr->OptionalHeader.MajorLinkerVersion);
	printf("Linker Ver. (Minor)        : %lX\n", nt_hdr->OptionalHeader.MinorImageVersion);
	printf("Size of Code               : %lX\n", nt_hdr->OptionalHeader.SizeOfCode);
	printf("Size of Initialized Data   : %lX\n", nt_hdr->OptionalHeader.SizeOfInitializedData);
	printf("Size of Uninitialized Data : %lX\n", nt_hdr->OptionalHeader.SizeOfUninitializedData);
	printf("Entry Point                : %lX\n", nt_hdr->OptionalHeader.AddressOfEntryPoint);
	printf("Base of Code               : %lX\n", nt_hdr->OptionalHeader.BaseOfCode);
	//printf("Base of Data               : %lX\n", nt_hdr->OptionalHeader.BaseOfData); /* x86 only */
	printf("Image Base                 : %lX\n", nt_hdr->OptionalHeader.ImageBase);
	printf("Section Alignment          : %lX\n", nt_hdr->OptionalHeader.SectionAlignment);
	printf("File Alignment             : %lX\n", nt_hdr->OptionalHeader.FileAlignment);
	printf("OS Ver. (Major)            : %lX\n", nt_hdr->OptionalHeader.MajorOperatingSystemVersion);
	printf("OS Ver. (Minor)            : %lX\n", nt_hdr->OptionalHeader.MinorOperatingSystemVersion);
	printf("Image Ver. (Major)         : %lX\n", nt_hdr->OptionalHeader.MajorImageVersion);
	printf("Image Ver. (Minor)         : %lX\n", nt_hdr->OptionalHeader.MinorImageVersion);
	printf("Subsystem Ver. (Major)     : %lX\n", nt_hdr->OptionalHeader.MajorSubsystemVersion);
	printf("Subsystem Ver. (Minor)     : %lX\n", nt_hdr->OptionalHeader.MinorOperatingSystemVersion);
	printf("Win32 Version Value        : %lX\n", nt_hdr->OptionalHeader.Win32VersionValue);
	printf("Size of image              : %lX\n", nt_hdr->OptionalHeader.SizeOfImage);
	printf("Size of Headers            : %lX\n", nt_hdr->OptionalHeader.SizeOfHeaders);
	printf("Checksum                   : %lX\n", nt_hdr->OptionalHeader.CheckSum);
	printf("Subsystem                  : %lX    (%s)\n", nt_hdr->OptionalHeader.Subsystem, get_OptionalHeader_Subsystem(nt_hdr->OptionalHeader.Subsystem));
	printf("DLL Characteristics        : %lX\n", nt_hdr->OptionalHeader.DllCharacteristics);
	parse_OptionalHeader_DllCharacteristics(nt_hdr->OptionalHeader.DllCharacteristics);
	printf("Size of Stack Reserve      : %lX\n", nt_hdr->OptionalHeader.SizeOfStackReserve);
	printf("Size of Stack Commit       : %lX\n", nt_hdr->OptionalHeader.SizeOfStackCommit);
	printf("Size of Heap Reserve       : %lX\n", nt_hdr->OptionalHeader.SizeOfHeapCommit);
	printf("Size of Heap Commit        : %lX\n", nt_hdr->OptionalHeader.SizeOfHeapCommit);
	printf("Loader Flags               : %lX\n", nt_hdr->OptionalHeader.LoaderFlags);
	printf("Number of RVAs and Sizes   : %lX\n", nt_hdr->OptionalHeader.NumberOfRvaAndSizes);
	printf("\nData Directory                       Address     Size\n");

	for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1; i++) {
		printf("%-36s %-8lX    %lX\n", get_Data_Directory_Name(i), nt_hdr->OptionalHeader.DataDirectory[i].VirtualAddress, nt_hdr->OptionalHeader.DataDirectory[i].Size);
	}
}

static const char* get_Section_Header_Characteristics(UINT32 characteristic)
{
	static char buff[3] = "";
	buff[0] = characteristic & IMAGE_SCN_MEM_READ    ? 'r' : '-';
	buff[1] = characteristic & IMAGE_SCN_MEM_WRITE   ? 'w' : '-';
	buff[2] = characteristic & IMAGE_SCN_MEM_EXECUTE ? 'x' : '-';
	return buff;
}

void parse_section_header()
{
	printf("\n---------------------- Section Header -------------------------------\n");
	printf("Name        Raw Addr.    Raw size    Virtual Addr.    Virtual Size    Characteristics    Ptr to Reloc.    Num. of Reloc.    Num. of Linenum.\n");

	for (i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++) {
		printf("%-10.8s  ", section_hdr[i].Name);
		printf("%-12lX"   , section_hdr[i].PointerToRawData);
		printf("%-12lX "  , section_hdr[i].SizeOfRawData);
		printf("%-16lX "  , section_hdr[i].VirtualAddress);
		printf("%-15lX "  , section_hdr[i].Misc.VirtualSize);
		printf("%-8lX "   , section_hdr[i].Characteristics);
		printf("%-10.3s"  , get_Section_Header_Characteristics(section_hdr[i].Characteristics));
		printf("%-16lX "  , section_hdr[i].PointerToRelocations);
		printf("%-16lX  " , section_hdr[i].NumberOfRelocations);
		printf("%lX\n"    , section_hdr[i].NumberOfLinenumbers);
	}
}

static const DWORD RVA_2_Raw(DWORD RVA)
{
	int i;
	for (i = 0; i < nt_hdr->FileHeader.NumberOfSections - 1; i++)
		if (RVA < section_hdr[i + 1].VirtualAddress)
			break;

	return RVA - section_hdr[i].VirtualAddress + section_hdr[i].PointerToRawData;
}

void parse_IAT()
{
	DWORD import_base = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD import_size = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	INT32 descriptor_num = import_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	IMAGE_IMPORT_DESCRIPTOR* descriptor = file_addr + RVA_2_Raw(import_base);
	IMAGE_THUNK_DATA* data;
	UINT32 func_count;

	printf("\n---------------------- Import Address Table -------------------------------\n");
	printf("Offset    Name                                        Func. Count    Bound?    OriginalFirstThunk    TimeDateStamp    Forwarder    NameRVA    FirstThunk\n");

	for (i = 0; i < descriptor_num - 1; i++) {
		data = file_addr + RVA_2_Raw(descriptor[i].OriginalFirstThunk);
		func_count = -1;
		while (data[++func_count].u1.Function);

		printf("%-10.6lX", import_base + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
		printf("%-44.42s"    , file_addr + RVA_2_Raw(descriptor[i].Name));
		printf("%-15d"    , func_count);
		printf("%-10s"    , "unknown");
		printf("%-22.6lX" , descriptor[i].OriginalFirstThunk);
		printf("%-17d"    , descriptor[i].TimeDateStamp);
		printf("%-13lX"   , descriptor[i].ForwarderChain);
		printf("%-11lX"   , descriptor[i].Name);
		printf("%-lX"     , descriptor[i].FirstThunk);
		putc('\n', stdout);
	}
}

void parse_Resource()
{
	DWORD resource_base = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	DWORD resource_size = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Usage: %s <PE_file>\n", argv[0]);
		getchar();
		exit(-1);
	}

	LPCSTR filename = argv[1];
	init(filename);
	parse_dos_header();
	parse_nt_header();
	parse_section_header();
	parse_IAT();
	parse_Resource();

	return 0;
}