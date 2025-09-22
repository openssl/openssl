#!/bin/sh

# Run codespell on the OpenSSL tree.
# If you get a false positive here, the usual fix is to
# add it to the end of the -L list of ignored words, below.
#
# Any arguments provided (such as -w) are added to the
# codespell invocation.
#
# You can add this check to your git pre-commit hooks
# with something akin to the following:
# --------8<----------
#check_codespell_diff() {
#    spelling_mistakes=""
#    while read -r -d '' path; do
#        spelling_mistakes="`util/codespell-check.sh $path`"
#    done
#    if [ -n "$spelling_mistakes" ]; then
#        cat >&2 <<EOF
# -- Spelling Mistakes --
#The code you want to commit has spelling mistakes:
#
#$spelling_mistakes
#
#Fix them and then commit. See util/codespell-check.sh
#for more information
#EOF
#        exit 1
#    fi
#}
#git diff-index --cached -z --name-only "$against" \
#    | check_codespell_diff \
#    || exit 1
# ---------8<-----------

codespell --ignore-regex '\b[a-zA-Z][a-zA-Z]\b' \
	  -L 'ADDAD, addin, adin, allws, alo, Alo, alow, anS, Buda, buildd, bve, cann, CANN, ciph, Collison, consumation, DELET, dota, Durin, ect, ede, endianess, endin, engineerr, ENGINEerr, FILETEST, filetests, htmp, inbrace, ine, informat, ISCONNECTION, isnt, KEYPAIR, keyserver, larg, LOd, Manger, Merget, nclusion, NOo, OPTIO, outin, passin, poping, pris, rewinded, shouldnot, SHS, Sorce, sover, succes, testss, Thi, tmplate, tne, uis, usign, vew, Widgits, aas, Aas, AAS, abd, ABD, accreting, AFAIR, afile, afterAll, AfterAll, Ake, ALine, allEdges, alloced, alloco, ALS, alsptd, ang, ans, ANS, aNULL, archType, arithmetics, assertIn, atLeast, AtLeast, atMost, bootup, BRE, CAF, cant, Chang, checkin, childs, circularly, Circularly, claus, Claus, clen, CLOS, Collet, compilability, compileTime, CompileTime, complies, COMPLIES, configury, co-ordinate, co-ordinates, crasher, crashers, crate, Crate, CRATE, creat, CREAT, CrOS, crypted, CRYPTED, currentY, DAA, datas, debbugs, Debbugs, dependancies, dependancy, dependant, deque, Deque, doubleclick, doubleClick, DoubleClick, dout, Dout, DOUT, dum, dur, Dur, ECT, EDE, FileTest, flate, Flate, FLATE, fpr, FPR, FPT, gord, gost, Gost, GOST, Hart, hasTable, hel, hist, HIST, HSI, ifset, iif, IIF, implementor, Implementor, implementors, Implementors, inactivate, indention, indx, inh, inout, inOut, InOut, INOUT, ist, IST, keep-alives, keypair, keyPair, Keypair, KeyPair, keypairs, keyPairs, Keypairs, KeyPairs, LAMDA, leapYear, LOD, Maked, Manuel, ment, minimise, mis, Mis, MIS, mitre, Mitre, MITRE, mmaped, msdos, MSDOS, nam, Nam, NAM, Ned, nin, Nin, nmake, NMake, NMAKE, notin, Notin, NotIn, numer, OCE, offsetp, ois, onText, OnText, openin, OptIn, origN, paeth, Paeth, PAETH, parm, pARM, Parm, PARM, parms, pARMS, Parms, PARMs, PARMS, pass-thru, pres, Pres, prevEnd, PullRequest, que, readd, Readd, readded, Readded, regArg, regArgs, requestor, Requestor, requestors, re-usable, Re-usable, re-use, Re-use, re-used, Re-used, re-uses, Re-uses, re-using, Re-using, sav, SEH, ser, Ser, SER, servent, shouldBe, siz, SIZ, SME, SOM, splitted, statics, Statics, strRange, technics, therefor, Therefor, therefrom, thirdparty, thirdParty, Thirdparty, ThirdParty, THIRDPARTY, thru, Thur, THUR, tolen, tthe, UIs, upto, upTo, uptodate, upToDate, UpToDate, useable, Useable, userA, UserA, varN, vertexes, vor, WAN, Wirth, wont, WRONLY, WTH, roperties, igest, equest, equests, ategory, couldn, wasn, ture, biom, bion, sHolder' \
	  -S '*codespell-check.sh, */LICENSE, */test/danetest.in, */test/data2.bin, */test/recipes/30-test_evp_data/evppkey_kas.txt, */test/recipes/30-test_evp_data/evppkey.txt, */3rd*[pP]arty/*, */aspell/*, */charsets/*, */chrtrans/*, */codepage/*, */data/*, */deps/*, */dict/*, */dictionaries/*, */doc*/[a-df-z][a-z]/*, */doc*/[a-z][a-z][_-][a-zA-Z][a-zA-Z]/*, */doc*/e[a-mo-z]/*, */[eE]ncode/*, */[eE]ncodings/*, */extern/*, */external/*, */externals/*, */help/[a-df-z][a-z]/*, */help/[a-z][a-z]_[A-Z][A-Z]/*, */help/es/*, */i18n/*, */icu/*, */info/[a-df-z][a-z]/*, */info/[a-z][a-z]_[A-Z][A-Z]/*, */info/es/*, */intl/*, */l10n/*, */langmap/*, */langs/*, */[lL]ang/*, */[lL]anguage/*, */[lL]anguages/*, */*[lL]ocal[ei]*/*, */man*/[a-df-z][a-z]/*, */man*/[a-z][a-z][_-][a-zA-Z][a-zA-Z]/*, */man*/e[a-mo-z]/*, */messages[_./][a-df-z][a-z][_./]*, */messages[_./][a-z][a-z]_[A-Z][A-Z][_./]*, */messages[_./]es[_./]*, */[mM]ath[jJ]ax/*, */runtime/*, */[tT]hird*[pP]arty/*, */[tT]ranslation/*, */[tT]ranslations/*, */unicode/*, */Unicode/*, */unicore/*, */vendor/*, */vendors/*, */.versions/*, *_8h.html, *_8h_source.html, *.asc, */AUTHORS*, CONTRIBUTORS*, *.crt, *.css.map, */*.desktop, */*.desktop.in, *.eps, /fonts/*, *.fr.utf-8, *.git, *__*__*.html, *.html.de, *.html.es, *.html.fr, *.html.ko.euc-kr, *.html.pt-br, *.info_[0-9], *.ipynb, *.ja.utf8, *.js.map, */[lL]ocale, localization*-[a-z][a-z].*, localization*-[a-z][a-z]_[a-zA-Z][a-zA-Z].*, *lorem-ipsum*, */.mailmap, *.min.js, *.pdf, *.pem, *.po, *.ppm, *.ps, */rfc[1-9]*.txt, *.rtf, */searchindex.js, *.sum, *.svg, *.svn, THANKS*, *.tr.utf8, *.xpm, */yarn.lock, *.zh-cn.utf8, *.zlib, ABOUT-NLS, authors.xml, CREDITS, CREDITS.TXT, DONATIONS, jquery.js, jquery.min.map, MAINTAINERS, NormalizationTest.txt, package-lock.json, UnicodeData.txt, */*[^a/]test/*, */*[^a/]tests/*, */test*/*, [cC]hange.[lL]og*, [cC]hange[lL]og*, *[._-][cC]hanges, [cC]hanges[._-]*, CHANGE.log*, CHANGELOG*, *[._-]CHANGES, CHANGES[._-]*, [cC]hanges, CHANGES, *man[12345657]/*' \
	  $@
