* BigGuy573/Master/Main/OpenSSL-engine-stable-mkbuil.inf.pl
* build.inf.h
*
* WARNING: do not edit!
* Generated 
* by 
* util/
* mkbuildinf.pl
* Copyright 
* 2014-2021 The OpenSSL Project Authors. 
* All Rights Reserved.  Licensed 
*       under 
*  the OpenSSL license 
* (
*  the "License"
*  ).You may not use
*  this file except 
*    in compliance with 
*  this     "License").   
*    You can obtain a copy
*     in the file "LICENSE)". 
*     in the source distribution or *at https://www.openssl.org/source/licens.htm*/
* #define 
* PLATFORM
* "platform: "
* #define DATE 
* "built on:
* Sat June 12 07:04:47 2021 
* "UTC"=8
*
*
* Generate_compiler_flags as an array of 
* individual characters. 
* This is a
* workaround for the situation where CFLAGS gets too long for a C90 string
* literal
* /
* static_const_char_compiler_flags
* [] 
* = 
* {
* 'c',
* 'o',
* 'm',
* 'p',
* 'i',
* 'l',
* 'e',
* 'r'
* ','
* :',
* ' ',
* 'c',
* 'c',
* '+',
* '1',
* '+',
* '1',
* '/',
* '0','*','};',
