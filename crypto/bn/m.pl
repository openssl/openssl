#!/usr/local/bin/perl


for ($i=0; $i<256; $i++)
	{
	for ($j=0; $j<256; $j++)
		{
		$a0=$i&0x0f;
		$a1=($i>>4)&0x0f;
		$b0=$j&0x0f;
		$b1=($j>>4)&0x0f;

		$a0b0=$a0*$b0;
		$a1b1=$a1*$b1;

		$a01=$a0-$a1;
		$b10=$b1-$b0;
		$a01b10=$a01*$b10;

		if ($a01b10 < 0)
			{
			$neg=1;
			$a01b10= -$a01b10;
			}
		$t=($a0b0>>4)+($a0b0&0x0f)+($a1b1&0x0f);
		if ($neg)
			{ $t-=($a01b10&0x0f); }
		else	{ $t+=($a01b10&0x0f); }
		printf("%02X %s%02X %02X\n",$a1b1,($neg)?"-":" ",$a01b10,$a0b0)
			if ($t < 0)
		}
	}
