#build variables used by this project configuration
my $projectname="NT-$ARGV[0]-$ARGV[1]-$ARGV[2]-$ARGV[3]";
my $guid = "$ARGV[4]";
my $testguid = "$ARGV[5]";
my $winrtguid = "$ARGV[6]";
my $PlatformToolset="v120" ;
my $ToolsVersion="12.0";
my $vstoolversion="";
if($ARGV[1]=="8.1")
{
  $ToolsVersion="12.0";
  if($ARGV[0]=~/Phone/)
  {
    $PlatformToolset="v120_wp81";
    $vstoolversion.="wp8.1";
  }
  else
  {
    $PlatformToolset="v120";
    $vstoolversion.="ws8.1";
  }
}
else
{
  $ToolsVersion="12.0";
  if($ARGV[0]=~/Phone/)
  {
    $PlatformToolset="v110_wp80";
    $vstoolversion.="wp8.0";
  }
  else
  {
    $PlatformToolset="v110";
    $vstoolversion.="ws8.0";
  }
}
#add makefile project and test project to solution
open(my $solution, '>>', 'vsout\\openssl.sln') or die;

print $solution 'Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "'."$projectname".'", "'."$projectname\\$projectname.vcxproj".'", "{'."$guid".'}"
EndProject'."\r\n";

print $solution 'Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "'."$projectname".'-winrtcomponent", "'."$projectname-winrtcomponent\\$projectname-winrtcomponent.vcxproj".'", "{'."$winrtguid".'}"
'."\t".'ProjectSection(ProjectDependencies) = postProject
'."\t\t{$guid} = {$guid}".'
'."\t".'EndProjectSection
EndProject'."\r\n";

print $solution 'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "'."$projectname".'-testapp", "'."$projectname-testapp\\$projectname-testapp.csproj".'", "{'."$testguid".'}"
'."\t".'ProjectSection(ProjectDependencies) = postProject
'."\t\t{$winrtguid} = {$winrtguid}".'
'."\t".'EndProjectSection
EndProject'."\r\n";

close %solution;

sub replaceInFile {
  my($input,$output,%hash) =@_;
  open INPUT, $input or die "Cant Open $input";
  my $inputFile="";
  while (<INPUT>) { $inputFile .= $_ }
  close INPUT;
  foreach my $find ( keys %hash )
  {
    my $replace = $hash{$find};
    $inputFile =~ s/\Q$find\E/$replace/g;
  }


  open OUTPUT, '>', $output or die "Cant Open $output";
  print OUTPUT $inputFile;
  close OUTPUT;
}

{
  #create batch scripts for the makefile project
  open(my $build, '>', "vsout\\$projectname\\build.bat") or die;
  open(my $clean, '>', "vsout\\$projectname\\clean.bat") or die;
  open(my $rebuild, '>', "vsout\\$projectname\\rebuild.bat") or die;

  print $build "cd ..\\.. && call ms\\setVSVars.bat $vstoolversion\%2 && nmake -f vsout\\$projectname\\nt-%1-%2.mak init && nmake -f vsout\\$projectname\\nt-%1-%2.mak";
  print $clean "cd ..\\.. && nmake -f vsout\\$projectname\\nt-%1-%2.mak reallyclean";
  print $rebuild "cd ..\\.. && nmake -f vsout\\$projectname\\nt-%1-%2.mak reallyclean && call ms\\setVSVars.bat $vstoolversion%2 && nmake -f vsout\\$projectname\\nt-%1-%2.mak init && nmake -f vsout\\$projectname\\nt-%1-%2.mak";

  close $clean;
  close $build;
  close $rebuild;
}

{
  my (%replacement)=(
  'ToolsVersion="12.0"' => "ToolsVersion=\"$ToolsVersion\"",
  '<TargetFrameworkVersion>v8.0</TargetFrameworkVersion>' => "<TargetFrameworkVersion>v$ARGV[1]</TargetFrameworkVersion>",
  '<PlatformToolset>v120</PlatformToolset>' => "<PlatformToolset>$PlatformToolset</PlatformToolset>",
  '<PlatformToolset>v110_wp80</PlatformToolset>' => "<PlatformToolset>$PlatformToolset</PlatformToolset>",
  'guid' => "$guid",
  'testguid' => "$testguid",
  'winrtguid' => "$winrtguid",
  '<ApplicationTypeRevision>8.1</ApplicationTypeRevision>' => "<ApplicationTypeRevision>$ARGV[1]</ApplicationTypeRevision>"
  );
  if($ARGV[1] == "8.1"){
    #$replacement {'<Import Project="$(MSBuildExtensionsPath)\Microsoft\WindowsPhone\v$(TargetPlatformVersion)\Microsoft.Cpp.WindowsPhone.$(TargetPlatformVersion).targets" />'} ="";
    #$replacement {'<WinMDAssembly>true</WinMDAssembly>'}=
    #  "<ApplicationType>Windows $ARGV[0]</ApplicationType>\n<ApplicationTypeRevision>8.1</ApplicationTypeRevision>";
    #$replacement{"<CompileAsWinRT>true</CompileAsWinRT>"} = "";
    #$replacement{"WindowsSDK_MetadataPath"}="WindowsSDK_WindowsMetadata";

  }
  replaceInFile("ms\\vstemplates\\OpenSSLTestApp$ARGV[0]$ARGV[1]\\OpenSSLTestApp.csproj","vsout\\$projectname-testapp\\$projectname-testapp.csproj", %replacement);
  replaceInFile("ms\\vstemplates\\winrt$ARGV[0]$ARGV[1]\\winrt$ARGV[0]$ARGV[1].vcxproj","vsout\\$projectname-winrtcomponent\\$projectname-winrtcomponent.vcxproj", %replacement);
  replaceInFile("ms\\vstemplates\\Makefile$ARGV[0]\\Makefile$ARGV[0].vcxproj", "vsout\\$projectname\\$projectname.vcxproj", %replacement);
}

#############################################################################################
  #generate CPP file representing the batch file execution for the test-suite
use warnings;
my $filecpp = "vsout\\winrtcomponent.cpp";
my $function;
open(my $cpp, '>', $filecpp) or die "Could not open file '$filecpp' $!";
my $env = {};
foreach my $key (keys %ENV) {
  $env{$key}= $ENV{$key};
}
my $tc = 0;
sub tab{
  my $space="";
  for(my $i=0;$i<$tc;$i++){
    $space.="\t";
  }
  return $space;
}
my $totalTests=0;
my $fileID = 0;
# Function definition
my $binaries={};
my $inputs={};
my $outputs={};
sub processBatch{
   # get total number of arguments passed.
  my $ID =$fileID++;
  my $file = $_[0];

  $function.=tab()."{//call:@_\n";
  $tc++;
  my $info;
  my @paths = split(';',$env{"PATH"});
  unshift(@paths, '.');
  unshift(@paths, '.\\vsout\\');
  unshift(@paths, '.\\ms\\');
  my $opened = 0;
  for my $p (@paths)
  {
    my $pp = $p."\\".$file;
    if(open($info, $pp))
    {
      $opened=1;
      last;
    }
    if(open($info, $pp.".bat"))
    {
      $opened=1;
      last;
    }
  }
  $opened == 1 or die "Could not open $file: $!";
  my $count = 0;
  while( my $line = <$info>)  {
    #remove line break
    $line = substr($line,0,-1);
    #replace %i by its value
    for(my $i=20;$i>=0;$i--)
    {
      my $rep;
      if($i>$#_)
      {
        $rep="";
      }
      else
      {
        $rep=$_[$i];
      }
      $line =~ s/\%$i\%/$rep/g;
      $line =~ s/\%$i/$rep/g;
    }
    #replace environmental variables %var%
    foreach my $key (keys %env)
    {
      my $replace = $env{$key};
      my $find = "\%$key\%";
      $line =~ s/\Q$find\E/$replace/g;
    }

    my @words = split(' ', $line);
    if($#words==-1){
      $function.="\n";
      next;
    }
    if($words[0] eq "\@echo")
    {
      next;
    }
    if($words[0] eq "rem" )
    {
      $line=substr($line,4);
      $function.=tab()."//$line";
      next;
    }
    if($words[0] eq "set")
    {
      my $ind = index($line,"=");
      if(index($words[1],"=")!=-1)
      {
        my $var = (split('=',$words[1]))[0];
        my $val = substr($line, $ind+1);
        $env{$var}=$val;
        $function.=tab()."//set $var=\"$env{$var}\"\n";
        next;
      }

      next;
    }
    if($words[0] eq "echo")
    {
      my $msg="";
      for(my $i=1;$i<=$#words;$i++)
      {
        $msg.=$words[$i];
        if($i!=$#words)
        {
          $msg.=" ";
        }
      }
      $function.=tab()."echo(\"$msg\");\n";
      next;
    }
    if($words[0] eq "if" || $words[0] eq "IF")
    {
      $function.=tab()."if(errorlevel) goto $words[4]_$ID;\n";
      #$function.="//$line";
      #$function.=STDERR "$line";
      next;
    }
    if($words[0] eq "call")
    {
      splice @words, 0, 1;
      processBatch(@words);
      next;
    }
    if($words[0] eq "goto")
    {
      $function.=tab()."goto $words[1]_$ID;\n";
      next;
    }
    if(index($line,"=")!=-1)
    {
      my $ind = index($line,"=");
      my $var = (split('=',$line))[0];
      my $val = substr($line, $ind+1);
      $env{$var}=$val;
      $function.=tab()."//$var=\"$env{$var}\"\n";
      next;
    }
    if(index($line,":")!=-1)
    {
      my $label = substr($words[0],1);
      $function.=tab().$label."_".$ID.":\n";
      $function.=tab()."echo(\"".$label."_".$ID.":\");\n";
      next;
    }
    #parse executable calls
    # print STDERR "$words[0]-->\n";
    next if ($words[0]=~/cd/ || $words[0]=~/perl/ || $words[0]=~/del/ || $words[0]=~/fc.exe/);
    $binaries{"$words[0]"}=$line if($words[0]);
    $function.=tab()."{\n";
    $tc++;
    $function.=tab()."std::string argv[] = { ";
    my $argc = 0;
    for my $i (0..$#words) {
      next if ($words[$i]=~ />/); #any output goes to OutputDebugStream for store
      $argc++;
      if ($words[$i]=~ /..\\ms\\|..\\test\\/) {
          $inputs{$words[$i]} = 1;
          $words[$i] =~ s/..\\ms\\|..\\test\\//g;
      }
      #Compute runtime local folder for WinStore/WinPhone testing

      if($i> 0 && $words[$i-1]=~/-out|-CAserial|-keyout/ || $outputs{$words[$i]} ) {
        $outputs{$words[$i]} = 1;
        $function.="LocalFolderFile(\"$words[$i]\")";
      }
      else {
          $function.="\"$words[$i]\"";
      }

      if ($i != $#words) { $function.=", "; }
    }


    $function.=" };\n";
    $function.=tab()."dynload(L\"$words[0]\",$argc, argv, this);\n";
    $totalTests++;
    $tc--;
      $function.=tab()."}\n";
  }
  close $info;
  $tc--;
  $function.=tab()."}//end:@_\n";
}
$function='
{
  FILE *pCout, *pCerr;
  freopen_s(&pCout, LocalFolderFile("openssl.test.stdout.log").c_str(), "w", stdout);
  freopen_s(&pCerr, LocalFolderFile("openssl.test.stderr.log").c_str(), "w", stderr);
  errorlevel=0;
  ';
$tc++;
processBatch("ms\\test.bat");
$function.='
  fclose(pCout);
  fclose(pCerr);
  {
    OutputDebugStringA("---------------STDOUT-------------\n");
    std::ifstream file(LocalFolderFile("openssl.test.stdout.log"));
    std::string temp;
    while (std::getline(file, temp))
    {
      OutputDebugStringA(temp.c_str());
      OutputDebugStringA("\r\n");
    }
  }
  {
    OutputDebugStringA("---------------STDERR-------------\n");
    std::ifstream file(LocalFolderFile("openssl.test.stderr.log"));
    std::string temp;
    while (std::getline(file, temp))
    {
      OutputDebugStringA(temp.c_str());
      OutputDebugStringA("\r\n");
    }
  }
  return errorlevel;
}';
my $cppOutputFile = <<'END_MESSAGE';
#include "pch.h"
#include <string>
#include <stdlib.h>
#include <windows.h>
#include <thread>
#include <iostream>
#include <fstream>
#include "..\ms\vstemplates\winrtcomponent.h"
#define echo(A) OutputDebugStringA(A);OutputDebugStringA("\n");
typedef int (__cdecl *winrt_main)(int Argc, char *ARGV[]);
int errorlevel=0;

std::string LocalFolderFile(Platform::String^ file)
{
  auto path = Windows::Storage::ApplicationData::Current->LocalFolder->Path + "\\" + file;
  std::wstring tmp(path->Begin(), path->End());
  return std::string (tmp.begin(), tmp.end());
}

Platform::String^ charArrayToPlatformString(int argc, char **argv)
{
  Platform::String^ out = "";
  for (int i = 0; i < argc; i++)
  {
    std::string str(argv[i]);
    std::wstring wstr(str.begin(), str.end());
    out += ref new Platform::String(wstr.data(), wstr.length())+ " ";
  }
  return out;
}

void dynload(Platform::String^ modName, int argc, std::string* argv_const, winrtcomponent::testClass ^T)
{
  //Conversion from const char to char since openssl methods writes on these arguments...
  char **argv = NULL;
  HMODULE module = NULL;

  argv = new char*[argc];
  if (argv == NULL)
  {
    errorlevel = 1;
    goto cleanup;
  }
  memset(argv, 0, argc * sizeof(char*));

  for (int i = 0; i < argc; i++)
  {
    unsigned int l = argv_const[i].length();
    argv[i] = new char [l+1];
    if (argv[i] == NULL)
    {
      errorlevel = 1;
      goto cleanup;
    }

    for (unsigned j = 0; j < l; j++)
    {
      argv[i][j] = argv_const[i][j];
    }
    argv[i][l] = 0;
  }

  module = LoadPackagedLibrary(modName->Data(), 0);
  winrt_main pMain = (winrt_main) GetProcAddress(module, "winrt_main");
  if (!pMain)
  {
    errorlevel = 1;
    goto cleanup;
  }
  try
  {
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    int errorcode = pMain(argc, argv);
    QueryPerformanceCounter(&end);

    double interval = static_cast<double>(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    errorlevel |= errorcode;
    T->updateRun(charArrayToPlatformString(argc, argv), errorcode, interval);
  }
  catch (Platform::Exception ^e)
  {
    errorlevel = 1;
  }

cleanup:
  if (module != NULL)
  {
    FreeLibrary(module);
  }
  for (int i = 0; i < argc; i++)
  {
    if (argv[i] != NULL)
    {
      delete []argv[i];
    }
  }
  delete []argv;
}

int winrtcomponent::testClass::test()
END_MESSAGE
print $cpp "$cppOutputFile$function";
close $cpp;
#generate VSProject
sub addToProject{
  my ( $name ) = @_;
    return"<Content Include=\"$name\" >\n<CopyToOutputDirectory>Always</CopyToOutputDirectory>\n</Content>\n";
}

my @config=("Debug","Release");
my @arch=("Win32","arm");
my $rep="";
push(@arch, "x64") if($ARGV[0]=~/Store/);
for my $_config (@config) {
   for my $_arch (@arch) {
      my $suffix=$ARGV[2]=~/Dll/?"dll":"";
      my (%replacement)=(
      "OUT_D=out32$suffix" => "OUT_D=vsout\\$projectname\\$_config\\$_arch\\bin",
      "TMP_D=tmp32$suffix" => "TMP_D=vsout\\$projectname\\$_config\\$_arch\\tmp",
      );
      replaceInFile("vsout\\$projectname\\nt-$_config-$_arch.mak","vsout\\$projectname\\nt-$_config-$_arch.mak", %replacement);     
  }
}
foreach my $key (keys %binaries) {
  next if(!$binaries{$key} ||
    $key=~/.exe"/ ||
    $key=~/perl/ ||
    $key=~/del/ ||
    $key=~/cd/
    );
  $rep.=addToProject("\$(SolutionDir)\\$projectname\\\$(Configuration)\\\$(BuildConfiguration)\\bin\\$key.dll");
  $rep.=addToProject("\$(SolutionDir)\\$projectname\\\$(Configuration)\\\$(BuildConfiguration)\\bin\\$key.pdb");
}

$rep.=addToProject("\$(SolutionDir)\\$projectname\\\$(Configuration)\\\$(BuildConfiguration)\\tmp\\lib.pdb");
if($ARGV[2]=~/Dll/){
  $rep.=addToProject("\$(SolutionDir)\\$projectname\\\$(Configuration)\\\$(BuildConfiguration)\\bin\\libeay32.dll");
  $rep.=addToProject("\$(SolutionDir)\\$projectname\\\$(Configuration)\\\$(BuildConfiguration)\\bin\\ssleay32.dll");
}
foreach my $key (keys %inputs) {
  next if($key =~/\.out/);
  $rep.=addToProject("\$(SolutionDir)\\$key", \@config, \@arch);
}

$rep.=addToProject("\$(SolutionDir)\\..\\apps\\openssl.cnf");
$rep.=addToProject("\$(SolutionDir)\\..\\apps\\server.pem");
$rep.=addToProject("\$(SolutionDir)\\..\\apps\\client.pem");
{
  my $generated=<<'END_MESSAGE';
  <Choose>
    <When Condition=" '$(Platform)'=='x86' ">
      <PropertyGroup>
        <BuildConfiguration>Win32</BuildConfiguration>
      </PropertyGroup>
    </When>
    <When Condition=" '$(Platform)'=='x64' ">
      <PropertyGroup>
        <BuildConfiguration>x64</BuildConfiguration>
      </PropertyGroup>
    </When>
    <When Condition=" '$(Platform)'=='arm' ">
      <PropertyGroup>
        <BuildConfiguration>arm</BuildConfiguration>
      </PropertyGroup>
    </When>
  </Choose>
END_MESSAGE

  $generated.="<ItemGroup>$rep</ItemGroup>".
  "<ItemGroup><ProjectReference Include=\"..\\$projectname-winrtcomponent\\$projectname-winrtcomponent.vcxproj\">\n".
      "<Project>{$winrtguid}</Project>\n".
      "<Name>$projectname-winrtcomponent</Name>\n".
    "</ProjectReference></ItemGroup>";

my (%replacement)=('<!--GeneratedData-->'=>$generated);
  replaceInFile("vsout\\$projectname-testapp\\$projectname-testapp.csproj","vsout\\$projectname-testapp\\$projectname-testapp.csproj", %replacement);
}
