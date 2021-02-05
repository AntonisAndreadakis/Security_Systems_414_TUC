Andreadakis Antonios - 2013030059 - LAB41446117


## Description:

This is an access control logging system developed in C. The system keeps track of all file accesses and modifications.
More specifically, every file operation (such as open or modification) will generate an entry in a log file, stored for
further investigation by a separate high privileged process.
Program needs a `prog.c` program from user (included example), that will do stuff with files (open-fopen-write-fwrite) and
of course the files that the prog tries to access. It creates, with append mode, a file in same directory as the logfile.
As part of this assignment, we enriched our previous assignment with some extra functionality. In specific, we implement
a ransomware, which can create-select/encrypt/decrypt files. Given a directory as argument, is creates a big volume of files.


## Modes:

`logger.c`	: creates the log files and appends the file accesses information
`acmonitor.c`	: opens the logfile and performs checks
`test_aclog.c`	: tests above functionalities
`ransomware.sh`	: create-select/encrypt/decrypt files


## Running:

make all						->BUILD 
make run						->update logfile
./acmonitor -m						->run acmonitor for malicious users
./acmonitor -i filename					->run acmonitor for users accessed the specific file
make clean						->erase executable user's program and .so library


