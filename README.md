**Damn Small FI Scanner** (DSFS) is a fully functional FI scanner (supporting GET and POST parameters) written in under 100 lines of code.

As of optional settings it supports HTTP proxy together with HTTP header values "User-Agent", "Referer" and "Cookie".

```
$ python dsfs.py -h
Damn Small FI Scanner (DSFS) < 100 LoC (Lines of Code) #v0.1a
 by: Miroslav Stampar (@stamparm)

Usage: dsfs.py [options]

Options:
  --version          show program's version number and exit
  -h, --help         show this help message and exit
  -u URL, --url=URL  Target URL (e.g. "http://www.target.com/page.htm?id=1")
  --data=DATA        POST data (e.g. "query=test")
  --cookie=COOKIE    HTTP Cookie header value
  --user-agent=UA    HTTP User-Agent header value
  --random-agent     Use randomly selected HTTP User-Agent header value
  --referer=REFERER  HTTP Referer header value
  --proxy=PROXY      HTTP proxy address (e.g. "http://127.0.0.1:8080")
```

```
$ python dsfs.py -u ....

scan results: possible vulnerabilities found
```

p.s. Python v2.6 or v2.7 is required for running this program
