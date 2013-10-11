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

<img src="http://sharepix.ru/thmb/thmb201310/77u7vmarp6496273/image496273af.jpeg" alt="run" title="Run" />

select analyse two profs:

<img src="http://sharepix.ru/thmb/thmb201310/bcwd0vt1yx496274/image496274gt.jpeg" alt="two" title="Select Profs" />

answer to questions, wait, enjoy!

<img src="http://sharepix.ru/thmb/thmb201310/uh1rdnygsf496275/image496275lr.jpeg" alt="enjoy" title="Work Done" />

all actually executed trace from profiles will colored; funcs will dissect by groups, based on profiles:

<img src="http://sharepix.ru/thmb/thmb201310/hrumxv02cq496277/image496277vv.jpeg" alt="executed" title="Trace" />

some info about func grops:

<img src="http://sharepix.ru/thmb/thmb201310/6wz8iau2tb496278/image496278jb.jpeg" alt="info" title="Info" />

<img src="http://sharepix.ru/thmb/thmb201310/fhqpgkf5x8496279/image496279a8.jpeg" alt="info1" title="Info1" />

now, thats all, enjoy you work!
tnkx!

