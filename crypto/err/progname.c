#ifdef VMS

#pragma nostandard
#include <stdlib.h>
#include <rms>

void
ExtractProgName 
	(
	char 		*ImageName, 
	char 		**ProgName
	)
{
#if __INITIAL_POINTER_SIZE == 64
#pragma __required_pointer_size __save
#pragma __required_pointer_size 32
#endif
typedef char char_32;
char *TmpImageName;
#if __INITIAL_POINTER_SIZE == 64
#pragma __required_pointer_size __restore
#endif
char esa[NAM$C_MAXRSS],
     rsa[NAM$C_MAXRSS];
struct FAB fab;
struct NAM nam;
int status;

fab = cc$rms_fab;
nam = cc$rms_nam;

#if __INITIAL_POINTER_SIZE == 64
TmpImageName = (char_32 *)_malloc32 (strlen (ImageName) + 1);
#else
TmpImageName = (char *)malloc (strlen (ImageName) + 1);
#endif
strncpy (TmpImageName, ImageName, strlen (ImageName));
fab.fab$l_fna = TmpImageName;
fab.fab$b_fns = strlen (ImageName);
fab.fab$l_nam = &nam;

nam.nam$l_esa = esa;
nam.nam$b_ess = sizeof (esa);
nam.nam$l_rsa = rsa;
nam.nam$b_rss = sizeof (rsa);
nam.nam$v_synchk = 1;

status = SYS$PARSE (&fab);
if (! (status & 1))
   exit (status);

*ProgName = (char *)malloc (nam.nam$b_name + 1);
strncpy (*ProgName, nam.nam$l_name, nam.nam$b_name);
*(*ProgName + nam.nam$b_name) = '\0';

free (TmpImageName);
#pragma standard
}

#endif
