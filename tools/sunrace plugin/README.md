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

<img src="http://sharepix.ru/request/2y79d5nqj7aqkm01zmpzp954py2eywx1v4999wzr/image496280q6.jpeg" alt="run" title="Run" />

select analyse two profs:

<img src="http://sharepix.ru/request/6hvbg57qjjv4h4sd3vkw3lefkj6ntj3z1yah3g8m/image496281ln.jpeg" alt="two" title="Select Profs" />

answer to questions, wait, enjoy!

<img src="http://sharepix.ru/request/2n7rgx7g4p5mm5qwmzdobo2verzxz9f1vmsbjzsm/image496282sj.jpeg" alt="enjoy" title="Work Done" />

all actually executed trace from profiles will colored; funcs will dissect by groups, based on profiles:

<img src="http://sharepix.ru/request/uk0wlc720bxu3xs6ulsrhm8nj0lnjnfe8pat2hua/image4962834p.jpeg" alt="executed" title="Trace" />

some info about func grops:

<img src="http://sharepix.ru/request/efygkhtr7jomhs9zo5uzztaynut4jm0y28elp9dv/image496284bu.jpeg" alt="info" title="Info" />

<img src="http://sharepix.ru/request/pbvwpybkyfpzvi8z1xudtit5q9ye3d9so4pe31y1/image496279a8.jpeg" alt="info1" title="Info1" />

now, thats all, enjoy you work!
tnkx!

