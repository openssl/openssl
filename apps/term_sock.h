#ifndef TERM_SOCK_H
#define TERM_SOCK_H

/*
** Terminal Socket Function Codes
*/
#define TERM_SOCK_CREATE	1
#define TERM_SOCK_DELETE	2

/*
** Terminal Socket Status Codes
*/
#define TERM_SOCK_FAILURE	0
#define TERM_SOCK_SUCCESS	1

/*
** Terminal Socket Prototype
*/
int TerminalSocket (int FunctionCode, int *ReturnSocket);

#endif
