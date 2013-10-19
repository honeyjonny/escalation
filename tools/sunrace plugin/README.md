sunrace IDA Python plugin
=========================

Plugin combined DBI and Statical Analysis features

use valgrind-3.8.1 in tests


**first profile**
```
valgrind --tool=callgrind --trace-children=yes --collect-jumps=yes --dump-instr=yes --callgrind-out-file=ls.trace --separate-threads=yes ls
```

**second profile**
```
valgrind --tool=callgrind --trace-children=yes --collect-jumps=yes --dump-instr=yes --callgrind-out-file=ls.trace --separate-threads=yes ls - all
```


**what profit?**

run:

<img src="http://oi39.tinypic.com/vfcp6s.jpg" alt="run" title="Run" />

select analyse two profs:

<img src="http://oi42.tinypic.com/2141pp0.jpg" alt="two" title="Select Profs" />

answer to questions, wait, enjoy!

<img src="http://oi44.tinypic.com/2iuc2z8.jpg" alt="enjoy" title="Work Done" />

all actually executed trace from profiles will colored; funcs will dissect by groups, based on profiles:

<img src="http://oi42.tinypic.com/iol0yd.jpg" alt="executed" title="Trace" />

some info about func grops:

<img src="http://oi39.tinypic.com/21nh8vr.jpg" alt="info" title="Info" />

<img src="http://oi41.tinypic.com/2u8dyx3.jpg" alt="info1" title="Info1" />

now, thats all, enjoy you work!

want more?
just try!

tnkx!
