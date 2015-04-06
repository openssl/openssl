/* winrtdef.h
 * C source-detours for Windows Phone/Windows Store platform
 * written by Alejandro Jimenez Martinez
 * (aljim@microsoft.com) for the OpenSSL project 2014.
 */
#if defined(OPENSSL_WINAPP)
# define main winrt_main
//Include stdio.h to replace fprintf
# include<stdio.h>
# ifdef getenv
#  undef getenv
# endif
# ifdef setenv
#  undef setenv
# endif
# ifdef LoadLibraryA
#  undef LoadLibraryA
# endif
# ifdef GetTickCount
#  undef GetTickCount
# endif
# ifdef FindFirstFile
#  undef FindFirstFile
# endif
# define getenv winrt_getenv
# define setenv winrt_getenv
# define LoadLibraryA winrt_LoadLibraryA
# define GetTickCount winrt_GetTickCount
# define FindFirstFile(lpFileName, lpFindFileData) FindFirstFileEx(lpFileName, FindExInfoStandard, lpFindFileData, FindExSearchNameMatch, NULL, 0);

int winrt_GetTickCount(void);

void* winrt_LoadLibraryA(
    const char* lpFileName
  );
char* winrt_getenv(const char* varname);
int _kbhit();

int MoveFile(
    const wchar_t* lpExistingFileName,
    const wchar_t* lpNewFileName
    );

void* GetModuleHandle(
    const wchar_t* lpModuleName
    );

#endif