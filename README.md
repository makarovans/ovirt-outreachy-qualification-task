# ovirt-outreachy-qualification-task

## Analyzing libvirtd.log: ##

* There are several threads running and executing different jobs, the threads are distinguished by their numbers in the log file.
* __Goal__ is to find places where something _suspicious_ happens, such as that an __error occurs__, some __operation takes a long time__ or there is __something unusual__.

The __task__ is to create a __simple command line tool__ that finds and outputs information about _suspicious_ log parts to standard output. 

The tool will get the log file as its command line argument and produces
output that a human can use to quickly identify possible problems and to
find out where to look for more information about them and which virtual
machines are affected.

Some notes:
* Log files may be quite __large__ (can't load them whole into RAM).
* The format may vary and there are other log files in different formats, so it's best to be reasonably __flexible__ and
  __smart__.
  
## Command Line Tool ##

Run: 
```bash
./log_analyze.py [--n_jobs JOBS] [--full] log_file
```