/* Demo of use of error library */

#ifndef TEST_ERR_H
# define TEST_ERR_H

#ifdef  __cplusplus
extern "C" {
#endif

/* Test library name */

# define TEST_LIB_NAME   "demo test library routines"

/* Normal header details go here */

/*
 * Prototypes are picked up by the error script to generate strings for
 * function names.
 */

void a_test_function(void);

/*
 * Everything after this point is auto generated when you do "make errors"
 */
