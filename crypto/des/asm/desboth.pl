#!/usr/local/bin/perl

$L="edi";
$R="esi";

sub des_encrypt3
	{
	local($name,$enc)=@_;

	&function_begin($name,4,"");

	&comment("");
	&comment("Load the data words");
	&mov("ebx",&wparam(0));
	&mov($L,&DWP(0,"ebx","",0));
	&mov($R,&DWP(4,"ebx","",0));

	&comment("");
	&comment("IP");
	&IP_new($L,$R,"edx",0);

	# put them back
	
	if ($enc)
		{
		&mov(&DWP(4,"ebx","",0),$R);
		 &mov("eax",&wparam(1));
		&mov(&DWP(0,"ebx","",0),"edx");
		 &mov("edi",&wparam(2));
		 &mov("esi",&wparam(3));
		}
	else
		{
		&mov(&DWP(4,"ebx","",0),$R);
		 &mov("esi",&wparam(1));
		&mov(&DWP(0,"ebx","",0),"edx");
		 &mov("edi",&wparam(2));
		 &mov("eax",&wparam(3));
		}
	&push(($enc)?"1":"0");
	&push("eax");
	&push("ebx");
	&call("des_encrypt2");
	&push(($enc)?"0":"1");
	&push("edi");
	&push("ebx");
	&call("des_encrypt2");
	&push(($enc)?"1":"0");
	&push("esi");
	&push("ebx");
	&call("des_encrypt2");

	&mov($L,&DWP(0,"ebx","",0));
	&add("esp",36);
	&mov($R,&DWP(4,"ebx","",0));

	&comment("");
	&comment("FP");
	&FP_new($L,$R,"eax",0);

	&mov(&DWP(0,"ebx","",0),"eax");
	&mov(&DWP(4,"ebx","",0),$R);

	&function_end($name);
	}


