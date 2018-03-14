/* winrtdef.h
 * C source-detours for Windows Phone/Windows Store platform
 * written by Alejandro Jimenez Martinez
 * (aljim@microsoft.com) for the OpenSSL project 2014.
 */

#ifdef _WIN64
#define SIXTY_FOUR_BIT_LONG
#pragma warning(disable:4267)
#pragma warning(disable:4244)
#pragma warning(disable:4311)
#endif

#if defined(OPENSSL_WINAPP)
//Include stdio.h to replace fprintf
# include<stdio.h>
# ifdef getenv
#  undef getenv
# endif
# ifdef setenv
#  undef setenv
# endif

/*
# ifdef FindFirstFile
#  undef FindFirstFile
# endif
# define FindFirstFile(lpFileName, lpFindFileData) FindFirstFileEx(lpFileName, FindExInfoStandard, lpFindFileData, FindExSearchNameMatch, NULL, 0);

# ifdef GetTickCount
#  undef GetTickCount
# endif
# define GetTickCount winrt_GetTickCount

# ifdef LoadLibraryA
#  undef LoadLibraryA
# endif
# define LoadLibraryA winrt_LoadLibraryA
*/

# ifdef GetModuleHandle
#   undef GetModuleHandle
# endif
# define GetModuleHandle winrt_GetModuleHandle

# ifdef GetVersionEx
#   undef GetVersionEx
# endif
#define GetVersionEx winrt_GetVersionEx

int winrt_GetTickCount(void);

void* LoadLibraryA(
	const char* lpFileName
  );
char* getenv(const char* varname);
int _kbhit();

int MoveFile(
	const wchar_t* lpExistingFileName,
	const wchar_t* lpNewFileName
	);

HMODULE
winrt_GetModuleHandle(
	const wchar_t* lpModuleName
	);

#endif