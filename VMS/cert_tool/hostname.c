
#ifdef VMS
#pragma module HOSTNAME "X-1"

/*
**
** Copyright (c) 2000 Compaq Computer Corporation
** COMPAQ Registered in U.S. Patent and Trademark Office.
**
** Confidential computer software. Valid license from Compaq or
** authorized sublicensor required for possession, use or copying.
** Consistent with FAR 12.211 and 12.212, Commercial Computer Software,
** Computer Software Documentation, and Technical Data for Commercial
** Items are licensed to the U.S. Government under vendor's standard
** commercial license.
**
*/

/*
**++
**
**  FACILITY:  Apache Web Server
**
**  ABSTRACT:
**
**	This program determine the hostname of the default node or of
**	a given hostaddr.
**
**	The command line syntax is:
**
**	    HOSTNAME [-l log-name] [-s sym-name] [host-addr]
**
**	where:
**
**	    -l log-name	    specifies an optional logical name to receive hostname.
**
**	    -c sym-name	    specifies an optional symbol name to receive hostname.
**
**	    host-addr	    specifies an optional host address to resolve.
**
**  AUTHOR:  Matthew Doremus			CREATION DATE:  07-Jul-2000
**
**  Modification History:
**
**	X-1	Matthew Doremus				07-Jul-2000
**		Initial development
**
**--
**
**  Compile/Link instructions:
**
**	OpenVMS Alpha/VAX:
**	    $ CC HOSTNAME+SYS$LIBRARY:SYS$LIB_C/LIBRARY
**	    $ LINK HOSTNAME
**
*/

/*
** Define __NEW_STARLET if it's not already defined
*/
#ifndef __NEW_STARLET
#define __NEW_STARLET
#define __NEW_STARLET_SET
#endif

/*
** Include the necessary header files
*/
#include <lib$routines>
#include <libclidef>
#include <descrip>
#include <stdlib>
#include <string>
#include <stdio>
#include <netdb>
#include <in>
#include <socket>

/*
** Undefine __NEW_STARLET if we had defined it
*/
#ifndef __NEW_STARLET_SET
#undef  __NEW_STARLET_SET
#undef  __NEW_STARLET
#endif

/*
** Option Data Structure
*/
typedef struct _opt_data {
    char		*log_name;
    char		*sym_name;
    unsigned char	host_addr[4]; 
    } OPT_DATA;

/*
** Local Routine Prototypes
*/
static void 
ParseCmdLine (
    int,
    char *[],
    OPT_DATA *);

static void
SetLogName (
    char *,
    char *);

static void
SetSymName (
    char *,
    char *);

static void 
Usage ();

/*
**
**  main - Main processing routine for the HOSTNAME utility
**
**  Functional Description:
**
**	This routine controls overall program execution.
**
**  Usage:
**
**      main argc, argv, envp
**
**  Formal parameters:
**
**      argc 		- (IN) argument count
**      argv         	- (IN) address of an argument array 
**      envp         	- (IN) address of an environment string 
**
**  Implicit Parameters:
**
**      None
**
**  Routine Value:
**
**      None
**
**  Side Effects:
**
**      None
**
*/
int
main (
    int		argc,
    char	*argv[],
    char	*envp[]
    )
{
struct in_addr host_addr;
char hostname[512+1];
struct hostent *hp;
OPT_DATA OptData;
int i;

/*
** Parse the command line
*/
ParseCmdLine (argc, argv, &OptData);

/*
** If no host address was given, then use gethostname otherwise
** use gethostbyaddr.
*/
if (! OptData.host_addr[0] && ! OptData.host_addr[1] && 
    ! OptData.host_addr[2] && ! OptData.host_addr[3])
    {
    if (gethostname (hostname, sizeof (hostname) - 1))
        {
        perror ("gethostname");
        exit (1);
        }

    if (! (hp = gethostbyname (hostname)))
	{
        perror ("gethostbyname");
	exit (1);
	}
    }
else
    {
    host_addr.s_net = OptData.host_addr[0];
    host_addr.s_host = OptData.host_addr[1];
    host_addr.s_lh = OptData.host_addr[2];
    host_addr.s_impno = OptData.host_addr[3];
    	
    if (! (hp = gethostbyaddr (&host_addr, sizeof (host_addr), AF_INET)))
	{
        perror ("gethostbyaddr");
	exit (1);
	}
    }

/*
** Let's try to determine the best available fully qualified hostname.
*/
if (hp->h_name)
    {
    strcpy (hostname, hp->h_name);
    if (! strchr (hostname, '.'))
	{
	for (i = 0; hp->h_aliases[i]; i++)
	    {
	    if (strchr (hp->h_aliases[i], '.') && 
	        ! strncasecmp (hp->h_aliases[i], hostname, strlen (hostname)))
		{     
		strcpy (hostname, hp->h_aliases[i]);
		break;
		}
	    }
	}
    }
else
    strcpy (hostname, "(unavailable)");

/*
** Define a logical name if one was provided
*/
if (OptData.log_name)
    SetLogName (OptData.log_name, hostname);

/*
** Define a symbol name if one was provided
*/
if (OptData.sym_name)
    SetSymName (OptData.sym_name, hostname);

/*
** print the host name if no logical or symbol name was provided
*/
if (! OptData.log_name && ! OptData.sym_name)
    printf ("%s\n", hostname);

}

/*
**
**  ParseCmdLine - Parse the command line options
**
**  Functional Description:
**
**      This routine parses the command line options.
**
**  Usage:
**
**      ParseCmdLine argc, argv, OptData
**
**  Formal parameters:
**
**      argc 		- (IN) argument count
**      argv         	- (IN) address of an argument array 
**      OptData		- (OUT) address of command option data structure 
**			  which will contain the parsed input.
**
**  Implicit Parameters:
**
**      None
**
**  Routine Value:
**
**      None
**
**  Side Effects:
**
**      None
**
*/
static void
ParseCmdLine (
    int			argc,
    char		*argv[],
    OPT_DATA		*OptData
    )
{
int option,
    i;

/*
** Initialize the option data
*/
OptData->log_name = NULL;
OptData->sym_name = NULL;
OptData->host_addr[0] = 0;
OptData->host_addr[1] = 0;
OptData->host_addr[2] = 0;
OptData->host_addr[3] = 0;

/*
** Process the command line options
*/
while ((option = getopt (argc, argv, "l:s:?")) != EOF) 
    {
    switch (option) 
	{
	/* 
	** Output to logical name ?
	*/
	case 'l':
	    OptData->log_name = strdup (optarg);
	    break;

	/* 
	** Output to symbol name ?
	*/
	case 's':
	    OptData->sym_name = strdup (optarg);
	    break;

	/* 
	** Invalid argument ?
	*/
	case '?':
	default:
	    Usage ();
	    exit (1);
	    break;
	}
    }

/*
** Are the number of parameters correct ?
*/
if (argc - optind > 1)
    {
    Usage ();
    exit (1);
    }

/*
** Host Address provided ?
*/
if (argc - optind == 1)
    {
    char *addr_ptr = argv[optind],
         *addr_sep;

    for (i = 0; i < 4; i++)
	{
        if ((addr_sep = strchr (addr_ptr, '.')) && (i < 3))
	    *addr_sep = '\0';

	if (strlen (addr_ptr) == 0 || atoi (addr_ptr) > 255 ||
	    strspn (addr_ptr, "0123456789") != strlen (addr_ptr))
	    {
	    printf ("Invalid TCP/IP address format.\n");
	    exit (1);
	    }

	OptData->host_addr[i] = atoi (addr_ptr);
	if (addr_sep)
	    addr_ptr = addr_sep + 1;
	}    
    }
}

/*
**
**  SetLogName - Set a logical name & value
**
**  Functional Description:
**
**      This routine sets a logical name & value.
**
**  Usage:
**
**      SetLogName LogName, LogValue
**
**  Formal parameters:
**
**      LogName		- (IN) address of the logical name
**      LogValue       	- (IN) address of the logical value
**
**  Implicit Parameters:
**
**      None
**
**  Routine Value:
**
**      None
**
**  Side Effects:
**
**      None
**
*/
static void
SetLogName (
    char 		*LogName,
    char		*LogValue
    )
{
struct dsc$descriptor_s log_nam_desc = {0, DSC$K_DTYPE_T, DSC$K_CLASS_S, 0};
struct dsc$descriptor_s log_val_desc = {0, DSC$K_DTYPE_T, DSC$K_CLASS_S, 0};
int status;

/*
** Setup the logical name & value descriptors
*/
log_nam_desc.dsc$w_length = strlen (LogName);
log_nam_desc.dsc$a_pointer = LogName;
log_val_desc.dsc$w_length = strlen (LogValue);
log_val_desc.dsc$a_pointer = LogValue;

/*
** Set the logical name & value
*/
status = lib$set_logical (&log_nam_desc, &log_val_desc, 0, 0, 0);
if (! (status & 1))
    exit (status);

}

/*
**
**  SetSymName - Set a symbol name & value
**
**  Functional Description:
**
**      This routine sets a symbol name & value.
**
**  Usage:
**
**      SetSymName SymName, SymValue
**
**  Formal parameters:
**
**      SymName		- (IN) address of the symbol name
**      SymValue       	- (IN) address of the Symbol value
**
**  Implicit Parameters:
**
**      None
**
**  Routine Value:
**
**      None
**
**  Side Effects:
**
**      None
**
*/
static void
SetSymName (
    char 		*SymName,
    char		*SymValue
    )
{
struct dsc$descriptor_s sym_nam_desc = {0, DSC$K_DTYPE_T, DSC$K_CLASS_S, 0};
struct dsc$descriptor_s sym_val_desc = {0, DSC$K_DTYPE_T, DSC$K_CLASS_S, 0};
int status;

/*
** Setup the symbol name & value descriptors
*/
sym_nam_desc.dsc$w_length = strlen (SymName);
sym_nam_desc.dsc$a_pointer = SymName;
sym_val_desc.dsc$w_length = strlen (SymValue);
sym_val_desc.dsc$a_pointer = SymValue;

/*
** Set the symbol name & value
*/
status = lib$set_symbol (&sym_nam_desc, &sym_val_desc, &LIB$K_CLI_LOCAL_SYM);
if (! (status & 1))
    exit (status);

}

/*
**
**  Usage - Display the acceptable unix style command usage
**
**  Functional Description:
**
**      This routine displays to standard output the appropriate unix style 
**	command usage.
**
**  Usage:
**
**      Usage 
**
**  Formal parameters:
**
**      None
**
**  Implicit Parameters:
**
**      None
**
**  Routine Value:
**
**      None
**
**  Side Effects:
**
**      None
**
*/
static void
Usage ()
{

fprintf (stdout, "Usage: HOSTNAME [-l log-name] [-s sym-name] [host-addr]\n");

}
#endif      /* #ifdef VMS */
