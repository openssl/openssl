/* This header declares the necessary definitions for using the exponentiation
 * acceleration capabilities, and rnd number generation of the AEP card. 
 *
 */

/*
 *
 * Some AEP defines
 *
 */

/*Successful return value*/
#define AEP_R_OK                                0x00000000

/*Miscelleanous unsuccessful return value*/
#define AEP_R_GENERAL_ERROR                     0x10000001

/*Insufficient host memory*/
#define AEP_R_HOST_MEMORY                       0x10000002

#define AEP_R_FUNCTION_FAILED                   0x10000006

/*Invalid arguments in function call*/
#define AEP_R_ARGUMENTS_BAD                     0x10020000

#define AEP_R_NO_TARGET_RESOURCES				0x10030000

/*Error occuring on socket operation*/
#define AEP_R_SOCKERROR							0x10000010

/*Socket has been closed from the other end*/
#define AEP_R_SOCKEOF							0x10000011

/*Invalid handles*/
#define AEP_R_CONNECTION_HANDLE_INVALID         0x100000B3

#define AEP_R_TRANSACTION_HANDLE_INVALID		0x10040000

/*Transaction has not yet returned from accelerator*/
#define AEP_R_TRANSACTION_NOT_READY				0x00010000

/*There is already a thread waiting on this transaction*/
#define AEP_R_TRANSACTION_CLAIMED				0x10050000

/*The transaction timed out*/
#define AEP_R_TIMED_OUT							0x10060000

#define AEP_R_FXN_NOT_IMPLEMENTED				0x10070000

#define AEP_R_TARGET_ERROR						0x10080000

/*Error in the AEP daemon process*/
#define AEP_R_DAEMON_ERROR						0x10090000

/*Invalid ctx id*/
#define AEP_R_INVALID_CTX_ID					0x10009000

#define AEP_R_NO_KEY_MANAGER					0x1000a000

/*Error obtaining a mutex*/
#define AEP_R_MUTEX_BAD                         0x000001A0

/*Fxn call before AEP_Initialise ot after AEP_Finialise*/
#define AEP_R_AEPAPI_NOT_INITIALIZED			0x10000190

/*AEP_Initialise has already been called*/
#define AEP_R_AEPAPI_ALREADY_INITIALIZED		0x10000191

/*Maximum number of connections to daemon reached*/
#define AEP_R_NO_MORE_CONNECTION_HNDLS			0x10000200

/*
 *
 * Some AEP Type definitions
 *
 */

/* an unsigned 8-bit value */
typedef unsigned char				AEP_U8;

/* an unsigned 8-bit character */
typedef char					AEP_CHAR;

/* a BYTE-sized Boolean flag */
typedef AEP_U8					AEP_BBOOL;

/*Unsigned value, at least 16 bits long*/
typedef unsigned short				AEP_U16;

/* an unsigned value, at least 32 bits long */
#ifdef SIXTY_FOUR_BIT_LONG
typedef unsigned int				AEP_U32;
#else
typedef unsigned long				AEP_U32;
#endif

#ifdef SIXTY_FOUR_BIT_LONG
typedef unsigned long				AEP_U64;
#else
typedef struct { unsigned long l1, l2; }	AEP_U64;
#endif

/* at least 32 bits; each bit is a Boolean flag */
typedef AEP_U32			AEP_FLAGS;

typedef AEP_U8	    	*AEP_U8_PTR;
typedef AEP_CHAR    	*AEP_CHAR_PTR;
typedef AEP_U32			*AEP_U32_PTR;
typedef AEP_U64			*AEP_U64_PTR;
typedef void        	*AEP_VOID_PTR;

/* Pointer to a AEP_VOID_PTR-- i.e., pointer to pointer to void */
typedef AEP_VOID_PTR 	*AEP_VOID_PTR_PTR;

/*Used to identify an AEP connection handle*/
typedef AEP_U32					AEP_CONNECTION_HNDL;

/*Pointer to an AEP connection handle*/
typedef AEP_CONNECTION_HNDL 	*AEP_CONNECTION_HNDL_PTR;

/*Used by an application (in conjunction with the apps process id) to 
identify an individual transaction*/
typedef AEP_U32					AEP_TRANSACTION_ID;

/*Pointer to an applications transaction identifier*/
typedef AEP_TRANSACTION_ID 		*AEP_TRANSACTION_ID_PTR;

/*Return value type*/
typedef AEP_U32					AEP_RV;

#define MAX_PROCESS_CONNECTIONS 5

#define RAND_BLK_SIZE 1024

typedef enum{
        NotConnected=   0,
        Connected=              1,
        InUse=                  2
} AEP_CONNECTION_STATE;


typedef struct AEP_CONNECTION_ENTRY{
        AEP_CONNECTION_STATE    conn_state;
        AEP_CONNECTION_HNDL     conn_hndl;
} AEP_CONNECTION_ENTRY;


AEP_RV GetBigNumSize(void* ArbBigNum, AEP_U32* BigNumSize);
AEP_RV MakeAEPBigNum(void* ArbBigNum, AEP_U32 BigNumSize, unsigned char* AEP_BigNum);
AEP_RV ConvertAEPBigNum(void* ArbBigNum, AEP_U32 BigNumSize, unsigned char* AEP_BigNum);



typedef unsigned int t_AEP_OpenConnection(unsigned int *phConnection);

typedef unsigned int t_AEP_ModExp(unsigned int hConnection, void *a, void *p,
                                  void *n, void *r,AEP_U64 *tranid);

typedef unsigned int t_AEP_ModExpCrt(unsigned int hConnection,void *a, void *p,
                                  void *q, void *dmp1, void *dmq1,void *iqmp,
						  void *r,AEP_U64 *tranid);

typedef unsigned int t_AEP_GenRandom(AEP_CONNECTION_HNDL             hConnection,
                AEP_U32                                 Len,
                AEP_U32                                 Type,
                AEP_VOID_PTR                    pResult,
                AEP_TRANSACTION_ID*             pidTransID
        );



typedef unsigned int t_AEP_Initialize(AEP_VOID_PTR pInitArgs);
typedef unsigned int t_AEP_Finalize();
typedef unsigned int t_AEP_SetBNCallBacks(
                AEP_RV (*GetBigNumSizeFunc)(),
                AEP_RV (*MakeAEPBigNumFunc)(),
                AEP_RV (*ConverAEPBigNumFunc)()
        );

/* These are the static string constants for the DSO file name and the function
 * symbol names to bind to. 
*/
static const char *AEP_LIBNAME = "aep";

static const char *AEP_F1    = "AEP_ModExp";
static const char *AEP_F2    = "AEP_ModExpCrt";
static const char *AEP_F3    = "AEP_GenRandom";
static const char *AEP_F4    = "AEP_Finalize";
static const char *AEP_F5    = "AEP_Initialize";
static const char *AEP_F6    = "AEP_OpenConnection";
static const char *AEP_F7    = "AEP_SetBNCallBacks";
