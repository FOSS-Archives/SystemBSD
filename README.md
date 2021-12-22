this file explains my workflow/structuring habits and is meant only to
save mentor's time. ideally, this file will be deleted before "release"
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

