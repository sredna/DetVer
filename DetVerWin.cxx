/*
You probably want to build with /Zl /GS- /GR- /EHs-c- and link with /MANIFEST:NO
If you want this to run on Win95 and WinNT3.50, make sure you are not linking to msvcrt.dll and that the PE versions are set to <= 4.0.
If you want this to run on WinNT 3.10, make sure you are not linking to msvcrt.dll and that the PE versions are set to 3.10.
*/

#include <Windows.h>
#include <commctrl.h>
#include <Lm.h>
#include <stdarg.h>
#if _MSC_VER-0 > 1
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "comctl32.lib")
#endif

#define MKPTR(c,b,o) ( (c) (((char*)(b)) + (o)) )

static HMODULE LoadSysLib(LPCSTR Name)
{
	WCHAR wb[MAX_PATH];
	UINT cch = GetSystemDirectoryW(wb, ARRAYSIZE(wb));
	if (cch)
	{
		wsprintfW(wb + cch, L"\\%hs.dll", Name);
		return LoadLibraryW(wb);
	}
	if (sizeof(void*) < 8)
	{
		CHAR nb[MAX_PATH];
		cch = GetSystemDirectoryA(nb, ARRAYSIZE(nb));
		wsprintfA(nb + cch, "\\%s.dll", Name);
		return LoadLibraryA(nb);
	}
	return NULL;
}

static FARPROC GetSysProcAddr(LPCSTR Mod, LPCSTR Fun)
{
	HMODULE module_handle = LoadSysLib(Mod);
	return module_handle ? GetProcAddress(module_handle, Fun) : NULL;
}

static int PrintF(LPCSTR Fmt, ...) // No msvcrt on Win95.SP0
{
	va_list vl;
	va_start(vl, Fmt);
	CHAR buf[1024+!0];
	int cch = wvsprintfA(buf, Fmt, vl);
	HANDLE std_out = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD cb;
	if (!WriteFile(std_out, buf, cch, &cb, NULL)) cb = 0;
	va_end(vl);
	return cb;
}


EXTERN_C void __cdecl mainCRTStartup()
{
	FARPROC fp;
	BOOL is_wine = FALSE;
	BOOL is_reactos = FALSE;
	BOOL is_wow64 = FALSE;
	USHORT native_machine = 0, process_machine = 0;


	// *** Detect the native machine architecture ***
	HANDLE this_process = GetCurrentProcess();

	// IsWow64Process2 is the only API that tells the truth on ARM[64].
	if ((fp = GetSysProcAddr("KERNEL32", "IsWow64Process2")))
	{
		if (!((BOOL(WINAPI*)(HANDLE,USHORT*,USHORT*))fp)(this_process, &process_machine, &native_machine)) native_machine = 0;
	}
	if (!native_machine)
	{
		static const USHORT arcs[] = { 0x0000, 0x0009, 0x0006, 0x0005, 0x000c }; // PROCESSOR_ARCHITECTURE_*
		static const USHORT macs[] = { 0x014c, 0x8664, 0x0200, 0x01c4, 0xaa64 }; // IMAGE_FILE_MACHINE_*
		SYSTEM_INFO si;

		if (!(fp = GetSysProcAddr("KERNEL32", "GetNativeSystemInfo"))) fp = (FARPROC) &GetSystemInfo;
		((void(WINAPI*)(SYSTEM_INFO*))fp)(&si);

		for (UINT i = 0; i < ARRAYSIZE(arcs); ++i)
			if (arcs[i] == si.wProcessorArchitecture)
				native_machine = macs[i];
	}
	if (!process_machine)
	{
		HMODULE any_module = LoadSysLib("KERNEL32");
		IMAGE_NT_HEADERS*p = MKPTR(IMAGE_NT_HEADERS*, any_module, *MKPTR(UINT32*, any_module, 60));
		process_machine = p->FileHeader.Machine;
	}
	is_wow64 = sizeof(void*) < 8 && native_machine && process_machine != native_machine;


	// *** Get the shimmed Windows version ***
	DWORD win3ver = GetVersion();
	OSVERSIONINFOEXA ovi;
	ovi.dwMajorVersion = LOBYTE(win3ver);
	ovi.dwMinorVersion = HIBYTE(win3ver);
	ovi.dwBuildNumber = HIWORD(win3ver);
	ovi.dwPlatformId = (win3ver >> 30) ^ 0x2; // Magic VER_PLATFORM_WIN32* conversion
	ovi.szCSDVersion[0] = '\0';
	ovi.wServicePackMajor = ovi.wSuiteMask = ovi.wProductType = 0;

	// GetVersionExA does not exist on NT 3.10
	BOOL(WINAPI*GVEA)(OSVERSIONINFOA*);
	(FARPROC&) GVEA = GetSysProcAddr("KERNEL32", "GetVersionExA");
	ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
	if (GVEA && !GVEA((OSVERSIONINFOA*) &ovi))
	{
		ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
		GVEA((OSVERSIONINFOA*) &ovi);
	}


	// *** Detect Wine ***
	if (GetSysProcAddr("NTDLL", "wine_get_version")) ++is_wine; // This is the official way to detect Wine.
	HIMAGELIST (WINAPI*IL_C)(int, int, UINT, int, int); // NT 3.50 does not implement the ImageList
	if (!is_wine && ((FARPROC&)IL_C = GetSysProcAddr("COMCTL32", "ImageList_Create")))
	{
		// There are 5 implementations of the image list API. Wine does not match any of them.
		UINT dim = 16, flags = ILC_COLOR4|ILC_MASK|0x00003000;
		HIMAGELIST images = IL_C(dim, dim, flags, 0, 0);
		if (images)
		{
			UINT search = sizeof(void*) * 2, find_dim = 0, i;
			for (i = 0; i < 8 && !find_dim && *(SIZE_T*) images != 0x4c49; ++i)
				if (*MKPTR(UINT*, images, search + ((i + 0) * 4)) == dim 
				&& *MKPTR(UINT*, images, search + ((i + 1) * 4)) == dim)
					find_dim = search + (i * 4);
			is_wine |= find_dim && *MKPTR(UINT*, images, find_dim + (3 * 4)) == flags;
			((BOOL(WINAPI*)(HIMAGELIST))GetSysProcAddr("COMCTL32", "ImageList_Destroy"))(images);
		}
	}


	// *** Detect ReactOS ***
	is_reactos = !!LoadSysLib("NTDLL_Vista"); // A cheap trick that they will probably fix at some point


	// *** Detect the real Windows version ***
	BOOL at_least_winxp = ovi.dwMajorVersion > 5 || GetSysProcAddr("KERNEL32", "AddRefActCtx");
	if (!at_least_winxp)
	{
		ovi.dwBuildNumber &= 0xffff; // Mask away junk from Win9x
	}
	else
	{
		// GetVersion[Ex] cannot be trusted on WinXP+
		ovi.dwPlatformId = VER_PLATFORM_WIN32_NT;
		NET_API_STATUS(WINAPI*NABF)(void*);
		NET_API_STATUS(WINAPI*NSGI)(LPWSTR,DWORD,BYTE**);
		(FARPROC&) NABF = GetSysProcAddr("NETAPI32", "NetApiBufferFree");
		(FARPROC&) NSGI = GetSysProcAddr("NETAPI32", "NetServerGetInfo");
		SERVER_INFO_101*pSI;
		if (NSGI && !NSGI(NULL, 101, (BYTE**) &pSI))
		{
			if (ovi.dwMajorVersion != pSI->sv101_version_major || ovi.dwMinorVersion != pSI->sv101_version_minor)
			{
				ovi.dwBuildNumber = 0;
				ovi.szCSDVersion[0] = '\0';
				ovi.wServicePackMajor = ovi.wProductType = 0;
			}
			ovi.dwMajorVersion = pSI->sv101_version_major;
			ovi.dwMinorVersion = pSI->sv101_version_minor;
			NABF(pSI);
		}
	}

	CHAR osstrbuf[99];
	LPCSTR osstr = "?";
	USHORT winver = MAKEWORD(ovi.dwMinorVersion, ovi.dwMajorVersion);
	UINT build = ovi.dwBuildNumber;
	BOOL is_nt = ovi.dwPlatformId == VER_PLATFORM_WIN32_NT;

	if (winver < 0x0400 && sizeof(void*) < 8)
	{
		if (is_nt) wsprintfA(osstrbuf, "NT %u.%u", HIBYTE(winver), LOBYTE(winver)), osstr = osstrbuf;
		if (ovi.dwPlatformId == VER_PLATFORM_WIN32s) osstr = ("32s");
	}
	if ((winver|3) == (0x400|3)) osstr = is_nt ? ("NT 4") : ("95");
	if (winver == 0x40a && sizeof(void*) < 8) osstr = build >= 2183 ? ("98 SE") : ("98");
	if (winver == 0x45a && sizeof(void*) < 8) osstr = ("ME");
	if (winver == 0x500) osstr = ("2000");
	if (winver == 0x501) osstr = ("XP");
	if (winver == 0x502) osstr = ovi.wProductType == VER_NT_WORKSTATION ? ("XPx64") : GetSystemMetrics(SM_SERVERR2) ? ("2003 R2") : ("2003");
	if (winver == 0x600) osstr = ovi.wProductType <= VER_NT_WORKSTATION ? ("Vista") : ("2008");
	if (winver == 0x601) osstr = ovi.wProductType <= VER_NT_WORKSTATION ? ("7") : ("2008 R2");
	if (winver == 0x602) osstr = ovi.wProductType <= VER_NT_WORKSTATION ? ("8") : ("2012");
	if (winver == 0x603) osstr = ovi.wProductType <= VER_NT_WORKSTATION ? ("8.1") : ("2012 R2");
	if (winver == 0x604) osstr = ("10 Preview");
	if (winver == 0xa00) osstr = ("10");

	if (is_reactos || is_wine) PrintF("%s emulating ", is_reactos ? "ReactOS" : "Wine");
	PrintF("Windows %s", osstr);

	LPCSTR cpustr = 0;
	switch(native_machine)
	{
	case 0x014c: cpustr = "i386"; break;
	case 0x0200: cpustr = "IA64"; break;
	case 0x8664: cpustr = "AMD64"; break;
	case 0x01c4: cpustr = "ARM"; break;
	case 0xaa64: cpustr = "ARM64"; break;
	case 0x3a64: cpustr = "Hybrid"; break; // Can this even happen?
	}
	if (cpustr) PrintF(" on %s", cpustr);
	
	if (is_wow64) PrintF(" (WoW64)", cpustr);
	PrintF("\n");


	ExitProcess(0);
}
