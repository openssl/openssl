
#ifdef VMS
#pragma module HOSTADDR "X-1"

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
**	This program determine the hostaddr of the default node or of
**	a given hostname.
**
**	The command line syntax is:
**
**	    HOSTADDR [-l log-name] [-s sym-name] [host-name]
**
**	where:
**
**	    -l log-name	    specifies an optional logical name to receive hostname.
**
**	    -c sym-name	    specifies an optional symbol name to receive hostname.
**
**	    host-name	    specifies an optional host name to resolve.
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
**	    $ CC HOSTADDR+SYS$LIBRARY:SYS$LIB_C/LIBRARY
**	    $ LINK HOSTADDR
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
    char		*host_name; 
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
**  main - Main processing routine for the HOSTADDR utility
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
struct in_addr *addr_ptr;
char hostname[512+1];
struct hostent *hp;
OPT_DATA OptData;
char *hostaddr;
int addr_max,
    i;

/*
** Parse the command line
*/
ParseCmdLine (argc, argv, &OptData);

/*
** If no host name was given, then use gethostname otherwise
** use the host name given.
*/
if (! OptData.host_name)
    {
    if (gethostname (hostname, sizeof (hostname) - 1))
        {
        perror ("gethostname");
        exit (1);
        }
    }
else
    strcpy (hostname, OptData.host_name);

/*
** Get the host address using gethostbyname
*/
if (! (hp = gethostbyname (hostname)))
    {
    perror ("gethostbyname");
    exit (1);
    }

/*
** Format the host address(es) into a comma separated list
*/
addr_max = hp->h_length / sizeof (struct in_addr);
hostaddr = malloc ((addr_max * (15 + 1)) + 1);
addr_ptr = (struct in_addr *) hp->h_addr;
for (i = 0; i < addr_max; i++)
    {
    if (i > 0)
	strcat (hostaddr, ",");
    addr_ptr = addr_ptr + (i * sizeof (struct in_addr));
    sprintf (hostaddr + strlen (hostaddr), "%d.%d.%d.%d",
	addr_ptr->s_net, addr_ptr->s_host, 
	addr_ptr->s_lh, addr_ptr->s_impno);
    }

/*
** Define a logical name if one was provided
*/
if (OptData.log_name)
    SetLogName (OptData.log_name, hostaddr);

/*
** Define a symbol name if one was provided
*/
if (OptData.sym_name)
    SetSymName (OptData.sym_name, hostaddr);

/*
** print the host address if no logical or symbol name was provided
*/
if (! OptData.log_name && ! OptData.sym_name)
    printf ("%s\n", hostaddr);

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
OptData->host_name = NULL;

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
** Host Name provided ?
*/
if (argc - optind == 1)
    OptData->host_name = strdup (argv[optind]);

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

fprintf (stdout, "Usage: HOSTADDR [-l log-name] [-s sym-name] [host-name]\n");

}
#endif    /* #ifdef VMS */
