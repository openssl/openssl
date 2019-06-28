#ifndef HEADER_INTERNAL_PUNYCODE_H
# define HEADER_INTERNAL_PUNYCODE_H

/*
punycode.c from RFC 3492
http://www.nicemice.net/idn/
Adam M. Costello
http://www.nicemice.net/amc/

This is ANSI C code (C89) implementing Punycode (RFC 3492).

*/

/************************************************************/
/* Public interface (would normally go in its own .h file): */

enum punycode_status {
    punycode_success,
    punycode_bad_input,         /* Input is invalid.                       */
    punycode_big_output,        /* Output would exceed the space provided. */
    punycode_overflow           /* Input needs wider integers to process.  */
};

typedef unsigned int punycode_uint;

enum punycode_status punycode_encode(punycode_uint input_length,
                                     const punycode_uint input[],
                                     const unsigned char case_flags[],
                                     punycode_uint * output_length,
                                     char output[]);

    /* punycode_encode() converts Unicode to Punycode.  The input     */
    /* is represented as an array of Unicode code points (not code    */
    /* units; surrogate pairs are not allowed), and the output        */
    /* will be represented as an array of ASCII code points.  The     */
    /* output string is *not* null-terminated; it will contain        */
    /* zeros if and only if the input contains zeros.  (Of course     */
    /* the caller can leave room for a terminator and add one if      */
    /* needed.)  The input_length is the number of code points in     */
    /* the input.  The output_length is an in/out argument: the       */
    /* caller passes in the maximum number of code points that it     */
    /* can receive, and on successful return it will contain the      */
    /* number of code points actually output.  The case_flags array   */
    /* holds input_length boolean values, where nonzero suggests that */
    /* the corresponding Unicode character be forced to uppercase     */
    /* after being decoded (if possible), and zero suggests that      */
    /* it be forced to lowercase (if possible).  ASCII code points    */
    /* are encoded literally, except that ASCII letters are forced    */
    /* to uppercase or lowercase according to the corresponding       */
    /* uppercase flags.  If case_flags is a null pointer then ASCII   */
    /* letters are left as they are, and other code points are        */
    /* treated as if their uppercase flags were zero.  The return     */
    /* value can be any of the punycode_status values defined above   */
    /* except punycode_bad_input; if not punycode_success, then       */
    /* output_size and output might contain garbage.                  */

enum punycode_status punycode_decode(punycode_uint input_length,
                                     const char input[],
                                     punycode_uint * output_length,
                                     punycode_uint output[],
                                     unsigned char case_flags[]);

    /* punycode_decode() converts Punycode to Unicode.  The input is  */
    /* represented as an array of ASCII code points, and the output   */
    /* will be represented as an array of Unicode code points.  The   */
    /* input_length is the number of code points in the input.  The   */
    /* output_length is an in/out argument: the caller passes in      */
    /* the maximum number of code points that it can receive, and     */
    /* on successful return it will contain the actual number of      */
    /* code points output.  The case_flags array needs room for at    */
    /* least output_length values, or it can be a null pointer if the */
    /* case information is not needed.  A nonzero flag suggests that  */
    /* the corresponding Unicode character be forced to uppercase     */
    /* by the caller (if possible), while zero suggests that it be    */
    /* forced to lowercase (if possible).  ASCII code points are      */
    /* output already in the proper case, but their flags will be set */
    /* appropriately so that applying the flags would be harmless.    */
    /* The return value can be any of the punycode_status values      */
    /* defined above; if not punycode_success, then output_length,    */
    /* output, and case_flags might contain garbage.  On success, the */
    /* decoder will never need to write an output_length greater than */
    /* input_length, because of how the encoding is defined.          */


/************************************************************/
/* End of the RFC 3492 code */
int a2ulabel(const char *in, char *out, size_t *outlen);

int a2ucompare(const char *a, const char *u);
#endif
