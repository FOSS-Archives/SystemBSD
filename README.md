  ## Disclaimer: 
 The archived work in this repo (Ian Sutton's) was originally under an ISC-Type License, have sought permission for myself & have been granted permission by creator to: 
+ Sublicense and/or Multilicense, mainly under equivalent permissives used in other projects for example types that also provide the same permissions & conditions, even if worded differently for other software. 
 such as; MIT-1 or BSD-1-Clause & 2-Clause (Or other compliant BSD-Style) etc etc. 
- ***(But Never GPL)*** 
 
######   *(Please See the Licenses Folder for more options.)*      
  
##### Copyright (C) 2014, Ian Sutton (<ian@kremlin.cc>)
# Original Readme: 
  this section explains workflow/structuring habits 


 && saves time. ideally, this file will be deleted before "release"
and all files will follow standard protocol/KNF. 
 
------------------------------------------------------------------------
FILESYSTEM

/src - source files
	/src/modules/logind - obvious
	/src/modules/hostnamed - obvious
	/src/modules/localed - obvious
	/src/modules/timedated - obvious
/bin - dir for compiled test binaries, will eventually be build tmp dir
/build - build dir
/scripts - test scripts, mostly python scripts for gdb
------------------------------------------------------------------------
TODO

i keep a general informal list of TODO tasks in /TODO, as well as inline
TODOs in source. TODO tasks must be single line as the are delimited by
a newline character, this makes it so one can easily grep for TODO: and
get complete output. before release, /TODO should be deleted and "TODO:"
should never appear anywhere in any file.

additionally, any questions for mentors are written as comments and end
in ajacoutot@ or landry@, i use these if i can't catch y'all on IRC :)
------------------------------------------------------------------------
ETC

* make sure to end files newlines as their abscence confuses git

