/* This header declares the necessary definitions for using the exponentiation
 * acceleration capabilities of Atalla cards. The only cryptographic operation
 * is performed by "ASI_RSAPrivateKeyOpFn" and this takes a structure that
 * defines an "RSA private key". However, it is really only performing a
 * regular mod_exp using the supplied modulus and exponent - no CRT form is
 * being used. Hence, it is a generic mod_exp function in disguise, and we use
 * it as such.
 *
 * Thanks to the people at Atalla for letting me know these definitions are
 * fine and that they can be reproduced here.
 *
 * Geoff.
 */

typedef struct ItemStr
	{
	unsigned char *data;
	int len;
	} Item;

typedef struct RSAPrivateKeyStr
	{
	void *reserved;
	Item version;
	Item modulus;
	Item publicExponent;
	Item privateExponent;
	Item prime[2];
	Item exponent[2];
	Item coefficient;
	} RSAPrivateKey;

/* Predeclare the function pointer types that we dynamically load from the DSO.
 * These use the same names and form that Ben's original support code had (in
 * crypto/bn/bn_exp.c) unless of course I've inadvertently changed the style
 * somewhere along the way!
 */

typedef int tfnASI_GetPerformanceStatistics(int reset_flag,
					unsigned int *ret_buf);

typedef int tfnASI_GetHardwareConfig(long card_num, unsigned int *ret_buf);

typedef int tfnASI_RSAPrivateKeyOpFn(RSAPrivateKey * rsaKey,
					unsigned char *output,
					unsigned char *input,
					unsigned int modulus_len);

/* These are the static string constants for the DSO file name and the function
 * symbol names to bind to. Regrettably, the DSO name on *nix appears to be
 * "atasi.so" rather than something more consistent like "libatasi.so". At the
 * time of writing, I'm not sure what the file name on win32 is but clearly
 * native name translation is not possible (eg libatasi.so on *nix, and
 * atasi.dll on win32). For the purposes of testing, I have created a symbollic
 * link called "libatasi.so" so that we can use native name-translation - a
 * better solution will be needed. */
static const char *ATALLA_LIBNAME = "atasi";
static const char *ATALLA_F1 = "ASI_GetHardwareConfig";
static const char *ATALLA_F2 = "ASI_RSAPrivateKeyOpFn";
static const char *ATALLA_F3 = "ASI_GetPerformanceStatistics";

