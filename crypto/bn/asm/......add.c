#include <stdio.h>
	{
	unsigned long a[10],b[10],c[10];

	a[0]=0xFFFFFFFF;
	a[1]=0xFFFFFFFF;
	b[0]=0xFFFFFFFF;
	b[1]=0xFFFFFFFF;

	c[2]=bn_add_words(c,a,b,2);
	printf("%08X %08X %08X\n",c[2],c[1],c[0]);
	}
