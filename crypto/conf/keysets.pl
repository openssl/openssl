#!/usr/local/bin/perl

$NUMBER=0x01;
$UPPER=0x02;
$LOWER=0x04;
$EOF=0x08;
$WS=0x10;
$ESC=0x20;
$QUOTE=0x40;
$COMMENT=0x80;
$UNDER=0x100;

foreach (0 .. 127)
	{
	$v=0;
	$c=sprintf("%c",$_);
	$v|=$NUMBER	if ($c =~ /[0-9]/);
	$v|=$UPPER	if ($c =~ /[A-Z]/);
	$v|=$LOWER	if ($c =~ /[a-z]/);
	$v|=$UNDER	if ($c =~ /_/);
	$v|=$WS		if ($c =~ / \t\r\n/);
	$v|=$ESC	if ($c =~ /\\/);
	$v|=$QUOTE	if ($c =~ /['`"]/);
	$v|=$COMMENT	if ($c =~ /\#/);
	$v|=$EOF	if ($c =~ /\0/);

	push(@V,$v);
	}

print <<"EOF";
#define CONF_NUMBER		$NUMBER
#define CONF_UPPER		$UPPER
#define CONF_LOWER		$LOWER
#define CONF_EOF		$EOF
#define CONF_WS			$WS
#define CONF_ESC		$ESC
#define CONF_QUOTE		$QUOTE
#define CONF_COMMENT		$COMMENT
#define CONF_ALPHA		(CONF_UPPER|CONF_LOWER)
#define CONF_ALPHA_NUMERIC	(CONF_ALPHA|CONF_NUMBER|CONF_UNDER)
#define CONF_UNDER		$UNDER

#define IS_COMMENT(a)		(CONF_COMMENT&(CONF_type[(a)&0x7f]))
#define IS_EOF(a)		((a) == '\\0')
#define IS_ESC(a)		((a) == '\\\\')
#define IS_NUMER(a)		(CONF_type[(a)&0x7f]&CONF_NUMBER)
#define IS_WS(a)		(CONF_type[(a)&0x7f]&CONF_WS)
#define IS_ALPHA_NUMERIC(a)	(CONF_type[(a)&0x7f]&CONF_ALPHA_NUMERIC)
#define IS_QUOTE(a)		(CONF_type[(a)&0x7f]&CONF_QUOTE)

EOF

print "static unsigned short CONF_type[128]={";

for ($i=0; $i<128; $i++)
	{
	print "\n\t" if ($i % 8) == 0;
	printf "0x%03X,",$V[$i];
	}

print "\n\t};\n";
