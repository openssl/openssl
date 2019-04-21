/*
punycode.c from RFC 3492
http://www.nicemice.net/idn/
Adam M. Costello
http://www.nicemice.net/amc/

This is ANSI C code (C89) implementing Punycode (RFC 3492).

*/

/************************************************************/
/* Public interface (would normally go in its own .h file): */

#include <limits.h>

enum punycode_status {
    punycode_success,
    punycode_bad_input,         /* Input is invalid.                       */
    punycode_big_output,        /* Output would exceed the space provided. */
    punycode_overflow           /* Input needs wider integers to process.  */
};

#if UINT_MAX >= (1 << 26) - 1
typedef unsigned int punycode_uint;
#else
typedef unsigned long punycode_uint;
#endif

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

/**********************************************************/
/* Implementation (would normally go in its own .c file): */
#include <string.h>

/*** Bootstring parameters for Punycode ***/
enum { base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700,
    initial_bias = 72, initial_n = 0x80, delimiter = 0x2D
};

/* basic(cp) tests whether cp is a basic code point: */
#define basic(cp) ((punycode_uint)(cp) < 0x80)

/* delim(cp) tests whether cp is a delimiter: */
#define delim(cp) ((cp) == delimiter)

/* decode_digit(cp) returns the numeric value of a basic code */
/* point (for use in representing integers) in the range 0 to */
/* base-1, or base if cp is does not represent a value.       */

static punycode_uint decode_digit(punycode_uint cp)
{
    return cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 :
        cp - 97 < 26 ? cp - 97 : base;
}

/* encode_digit(d,flag) returns the basic code point whose value      */
/* (when used for representing integers) is d, which needs to be in   */
/* the range 0 to base-1.  The lowercase form is used unless flag is  */
/* nonzero, in which case the uppercase form is used.  The behavior   */
/* is undefined if flag is nonzero and digit d has no uppercase form. */

static char encode_digit(punycode_uint d, int flag)
{
    return d + 22 + 75 * (d < 26) - ((flag != 0) << 5);
    /*  0..25 map to ASCII a..z or A..Z */
    /* 26..35 map to ASCII 0..9         */
}

/* flagged(bcp) tests whether a basic code point is flagged */
/* (uppercase).  The behavior is undefined if bcp is not a  */
/* basic code point.                                        */

#define flagged(bcp) ((punycode_uint)(bcp) - 65 < 26)

/* encode_basic(bcp,flag) forces a basic code point to lowercase */
/* if flag is zero, uppercase if flag is nonzero, and returns    */
/* the resulting code point.  The code point is unchanged if it  */
/* is caseless.  The behavior is undefined if bcp is not a basic */
/* code point.                                                   */

static char encode_basic(punycode_uint bcp, int flag)
{
    bcp -= (bcp - 97 < 26) << 5;
    return bcp + ((!flag && (bcp - 65 < 26)) << 5);
}

/*** Platform-specific constants ***/

/* maxint is the maximum value of a punycode_uint variable: */
static const punycode_uint maxint = -1;
/* Because maxint is unsigned, -1 becomes the maximum value. */

/*** Bias adaptation function ***/

static punycode_uint adapt(punycode_uint delta, punycode_uint numpoints,
                           int firsttime)
{
    punycode_uint k;

    delta = firsttime ? delta / damp : delta >> 1;
    /* delta >> 1 is a faster way of doing delta / 2 */
    delta += delta / numpoints;

    for (k = 0; delta > ((base - tmin) * tmax) / 2; k += base) {
        delta /= base - tmin;
    }

    return k + (base - tmin + 1) * delta / (delta + skew);
}

/*** Main encode function ***/

enum punycode_status punycode_encode(punycode_uint input_length,
                                     const punycode_uint input[],
                                     const unsigned char case_flags[],
                                     punycode_uint * output_length,
                                     char output[])
{
    punycode_uint n, delta, h, b, out, max_out, bias, j, m, q, k, t;

    /* Initialize the state: */

    n = initial_n;
    delta = out = 0;
    max_out = *output_length;
    bias = initial_bias;

    /* Handle the basic code points: */
    for (j = 0; j < input_length; ++j) {
        if (basic(input[j])) {
            if (max_out - out < 2)
                return punycode_big_output;
            output[out++] =
                case_flags ? encode_basic(input[j], case_flags[j]) : input[j];
        }
        /* else if (input[j] < n) return punycode_bad_input; */
        /* (not needed for Punycode with unsigned code points) */
    }

    h = b = out;

    /* h is the number of code points that have been handled, b is the  */
    /* number of basic code points, and out is the number of characters */
    /* that have been output.                                           */

    if (b > 0)
        output[out++] = delimiter;

    /* Main encoding loop: */

    while (h < input_length) {
        /* All non-basic code points < n have been     */
        /* handled already.  Find the next larger one: */

        for (m = maxint, j = 0; j < input_length; ++j) {
            /* if (basic(input[j])) continue; */
            /* (not needed for Punycode) */
            if (input[j] >= n && input[j] < m)
                m = input[j];
        }

        /* Increase delta enough to advance the decoder's    */
        /* <n,i> state to <m,0>, but guard against overflow: */

        if (m - n > (maxint - delta) / (h + 1))
            return punycode_overflow;
        delta += (m - n) * (h + 1);
        n = m;

        for (j = 0; j < input_length; ++j) {
            /* Punycode does not need to check whether input[j] is basic: */
            if (input[j] < n /* || basic(input[j]) */ ) {
                if (++delta == 0)
                    return punycode_overflow;
            }

            if (input[j] == n) {
                /* Represent delta as a generalized variable-length integer: */

                for (q = delta, k = base;; k += base) {
                    if (out >= max_out)
                        return punycode_big_output;
                    t = k <= bias /* + tmin */ ? tmin : /* +tmin not needed */
                        k >= bias + tmax ? tmax : k - bias;
                    if (q < t)
                        break;
                    output[out++] = encode_digit(t + (q - t) % (base - t), 0);
                    q = (q - t) / (base - t);
                }

                output[out++] = encode_digit(q, case_flags && case_flags[j]);
                bias = adapt(delta, h + 1, h == b);
                delta = 0;
                ++h;
            }
        }

        ++delta, ++n;
    }

    *output_length = out;
    return punycode_success;
}

/*** Main decode function ***/

enum punycode_status punycode_decode(punycode_uint input_length,
                                     const char input[],
                                     punycode_uint * output_length,
                                     punycode_uint output[],
                                     unsigned char case_flags[])
{
    punycode_uint n, out, i, max_out, bias, b, j, in, oldi, w, k, digit, t;

    /* Initialize the state: */

    n = initial_n;
    out = i = 0;
    max_out = *output_length;
    bias = initial_bias;

    /* Handle the basic code points:  Let b be the number of input code */
    /* points before the last delimiter, or 0 if there is none, then    */
    /* copy the first b code points to the output.                      */

    for (b = j = 0; j < input_length; ++j)
        if (delim(input[j]))
            b = j;
    if (b > max_out)
        return punycode_big_output;

    for (j = 0; j < b; ++j) {
        if (case_flags)
            case_flags[out] = flagged(input[j]);
        if (!basic(input[j]))
            return punycode_bad_input;
        output[out++] = input[j];
    }

    /* Main decoding loop:  Start just after the last delimiter if any  */
    /* basic code points were copied; start at the beginning otherwise. */

    for (in = b > 0 ? b + 1 : 0; in < input_length; ++out) {

        /* in is the index of the next character to be consumed, and */
        /* out is the number of code points in the output array.     */

        /* Decode a generalized variable-length integer into delta,  */
        /* which gets added to i.  The overflow checking is easier   */
        /* if we increase i as we go, then subtract off its starting */
        /* value at the end to obtain delta.                         */

        for (oldi = i, w = 1, k = base;; k += base) {
            if (in >= input_length)
                return punycode_bad_input;
            digit = decode_digit(input[in++]);
            if (digit >= base)
                return punycode_bad_input;
            if (digit > (maxint - i) / w)
                return punycode_overflow;
            i += digit * w;
            t = k <= bias /* + tmin */ ? tmin : /* +tmin not needed */
                k >= bias + tmax ? tmax : k - bias;
            if (digit < t)
                break;
            if (w > maxint / (base - t))
                return punycode_overflow;
            w *= (base - t);
        }

        bias = adapt(i - oldi, out + 1, oldi == 0);

        /* i was supposed to wrap around from out+1 to 0,   */
        /* incrementing n each time, so we'll fix that now: */

        if (i / (out + 1) > maxint - n)
            return punycode_overflow;
        n += i / (out + 1);
        i %= (out + 1);

        /* Insert n at position i of the output: */

        /* not needed for Punycode: */
        /* if (decode_digit(n) <= base) return punycode_invalid_input; */
        if (out >= max_out)
            return punycode_big_output;

        if (case_flags) {
            memmove(case_flags + i + 1, case_flags + i, out - i);
            /* Case of last character determines uppercase flag: */
            case_flags[i] = flagged(input[in - 1]);
        }

        memmove(output + i + 1, output + i, (out - i) * sizeof *output);
        output[i++] = n;
    }

    *output_length = out;
    return punycode_success;
}

/**
 * Encode a code point using UTF-8
 * 
 * return number of bytes on success, 0 on failure (also produces U+FFFD, which uses 3 bytes)
 */
int codepoint2utf8(unsigned char *out, unsigned long utf)
{
    if (utf <= 0x7F) {
        // Plain ASCII
        out[0] = (unsigned char)utf;
        out[1] = 0;
        return 1;
    } else if (utf <= 0x07FF) {
        // 2-byte unicode
        out[0] = (unsigned char)(((utf >> 6) & 0x1F) | 0xC0);
        out[1] = (unsigned char)(((utf >> 0) & 0x3F) | 0x80);
        out[2] = 0;
        return 2;
    } else if (utf <= 0xFFFF) {
        // 3-byte unicode
        out[0] = (unsigned char)(((utf >> 12) & 0x0F) | 0xE0);
        out[1] = (unsigned char)(((utf >> 6) & 0x3F) | 0x80);
        out[2] = (unsigned char)(((utf >> 0) & 0x3F) | 0x80);
        out[3] = 0;
        return 3;
    } else if (utf <= 0x10FFFF) {
        // 4-byte unicode
        out[0] = (unsigned char)(((utf >> 18) & 0x07) | 0xF0);
        out[1] = (unsigned char)(((utf >> 12) & 0x3F) | 0x80);
        out[2] = (unsigned char)(((utf >> 6) & 0x3F) | 0x80);
        out[3] = (unsigned char)(((utf >> 0) & 0x3F) | 0x80);
        out[4] = 0;
        return 4;
    } else {
        // error - use replacement character
        out[0] = (unsigned char)0xEF;
        out[1] = (unsigned char)0xBF;
        out[2] = (unsigned char)0xBD;
        out[3] = 0;
        return 0;
    }
}

/*
 * Return values:
 * 1 - ok, *outlen contains valid buf length
 * 0 - ok but buf was too short, *outlen contains valid buf length
 * -1 - bad string passed
 */

int a2ulabel(const char *in, char *out, size_t *outlen)
{
    /* 
     * Domain name has some parts consisting of ASCII chars joined with dot.
     * If a part is shorter than 5 chars, it becomes U-label as is.
     * If it does not start with xn--,    it becomes U-label as is.
     * Otherwise we try to decode it. */
    char *outptr = out;
    const char *inptr = in;
    size_t size = 0;
    int result = 1;

    punycode_uint buf[256];     /* It's a hostname */
    if (out == NULL)
        result = 0;

    while (1) {
        char *tmpptr = strchr(inptr, '.');
        size_t delta = (tmpptr) ? tmpptr - inptr : strlen(inptr);

        if (strncmp(inptr, "xn--", 4) != 0) {
            size += delta + 1;

            if (size >= *outlen - 1)
                result = 0;

            if (result > 0) {
                memcpy(outptr, inptr, delta + 1);
                outptr += delta + 1;
            }
        } else {
            punycode_uint bufsize = 256;
            int i;

            if (punycode_decode(delta - 4, inptr + 4, &bufsize, buf, NULL) !=
                punycode_success)
                return -1;

            for (i = 0; i < bufsize; i++) {
                unsigned char seed[6];
                size_t utfsize = codepoint2utf8(seed, buf[i]);
                if (utfsize == 0)
                    return -1;

                size += utfsize;
                if (size >= *outlen - 1)
                    result = 0;

                if (result > 0) {
                    memcpy(outptr, seed, size);
                    outptr += size;
                }
            }

						if (tmpptr != NULL) {
							*outptr = '.';
							size++;
							if (size >= *outlen - 1)
								result = 0;
						}
        }

        if (tmpptr == NULL)
            break;

        inptr = tmpptr + 1;
    }

    return result;
}

/*
 * a MUST be A-label
 * u MUST be U-label
 * Returns 0 if compared values are equal
 * 1 if not
 * -1 in case of errors
 * */

int a2ucompare(const char *a, const char *u)
{
    char a_ulabel[512];
    size_t a_size = sizeof(a_ulabel);

    if (a2ulabel(a, a_ulabel, &a_size) <= 0) {
        return -1;
    }

    return (strcmp(a_ulabel, u) == 0) ? 0 : 1;
}
