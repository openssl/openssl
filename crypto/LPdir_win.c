/* $LP: LPlib/source/LPdir_win.c,v 1.1 2004/06/14 10:07:56 _cvs_levitte Exp $ */
/*
 * Copyright (c) 2004, Richard Levitte <richard@levitte.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <windows.h>
#ifndef LPDIR_H
#include "LPdir.h"
#endif

struct LP_dir_context_st
{
  WIN32_FIND_DATA ctx;
  HANDLE handle;
  char entry_name[NAME_MAX+1];
};

const char *LP_find_file(LP_DIR_CTX **ctx, const char *directory)
{
  struct dirent *direntry = NULL;

  if (ctx == NULL || directory == NULL)
    {
      errno = EINVAL;
      return 0;
    }

  errno = 0;
  if (*ctx == NULL)
    {
      *ctx = (LP_DIR_CTX *)malloc(sizeof(LP_DIR_CTX));
      if (*ctx == NULL)
	{
	  errno = ENOMEM;
	  free(*ctx);
	  return 0;
	}
      memset(*ctx, '\0', sizeof(LP_DIR_CTX));

#ifdef LP_SYS_WINCE
      {
	WCHAR *wdir = NULL;
	size_t index = 0;

	wdir = (WCHAR *)malloc((strlen(directory) + 1) * 2);
	if (wdir == NULL)
	  {
	    errno = ENOMEM;
	    free(*ctx);
	    free(wdir);
	    return 0;
	  }

	for (index = 0; index < strlen(directory) + 1; index++)
	  wdir[index] = (short)directory[index];

	(*ctx)->handle = FindFirstFile(wdir, &(*ctx)->ctx);

	free(wdir);
      }
#else
      (*ctx)->handle = FindFirstFile(directory, &(*ctx)->ctx);
#endif

      if ((*ctx)->handle == INVALID_HANDLE_VALUE)
	{
	  free(*ctx);
	  *ctx = NULL;
	  errno = EINVAL;
	  return 0;
	}
    }
  else
    {
      if (FindNextFile((*ctx)->handle, (*ctx)->ctx) == FALSE)
	{
	  return 0;
	}
    }

  strncpy((*ctx)->entry_name, (*ctx)->ctx.cFileName,
	  sizeof((*ctx)->entry_name));
  return (*ctx)->entry_name;
}

int LP_find_file_end(LP_DIR_CTX **ctx)
{
  if (ctx != NULL && *ctx != NULL)
    {
      FindClose((*ctx)->handle);
      free(*ctx);
      return 1;
    }
  errno = EINVAL;
  return 0;
}
