#!/usr/local/bin/perl
use ExtUtils::testlib;
use SSLeay;

$message=SSLeay::BN::new();
$e=SSLeay::BN::new();
$mod=SSLeay::BN::new();

$mod=SSLeay::BN::dec2bn("114381625757888867669235779976146612010218296721242362562561842935706935245733897830597123563958705058989075147599290026879543541");
$e=5;
$d=SSLeay::BN::dec2bn("45752650303155547067694311990458644804087318688496945025024737159778909096647814932594914301288138204957467016445183857236173773");

$message=SSLeay::BN::bin2bn("The magic words are squeamish ossifrage");


	$cipher_text=	$message->mod_exp($e,$mod);
print $mod."\n";
print $mod->num_bits()."\n";
for (1 .. 1000)
	{
	$clear=		$cipher_text->mod_exp($d,$mod);
	}
print $clear->bn2bin()."\n";
