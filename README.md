dns-web-scanner
===============

Scan a list of DNS domains for active HTTP services and redirects. Example:

```
$ ./dns_web_scanner.py schapiro.org www.schapiro.org schapiro.bad
http://schapiro.org/ OK
 ADDRESS 216.239.34.21 216.239.36.21 216.239.38.21 216.239.32.21
 REDIRECT 301 http://www.schapiro.org/
http://www.schapiro.org/ OK
 ALIAS ghs.google.com
 ADDRESS 173.194.65.121
http://schapiro.bad/ BAD
 RESOLVED NODATA schapiro.bad
```

We use it to make sure that our numerous DNS domains point to something useful.

Requires `python-cheetah` and `python-adns`.

Usage:
------

```
$ ./dns_web_scanner.py --help
usage: dns_web_scanner.py [-h] [-V] [-v] [-H | -C] [-w] [-o FILE]
                          TARGET [TARGET ...]

Read DNS names or URLs from CSV files or command line. The name will be checked for
a valid DNS response (CNAME or A) and a working web server on port 80. HTTP
and (I)FRAME redirects will be followed and checked.

(I)FRAME redirects is something we want to get rid off, so they count as an error.

CSV files are ;-separated and the first line (headers) is skipped. Only the first element
from the CSV file is used and should be a host or URL without the http:// prefix.

Created by Schlomo Schapiro
Copyright 2013 ImmobilienScout24. All rights reserved.

Licensed under the GNU General Public License
http://www.gnu.org/licenses/gpl.html

Homepage: http://github.com/ImmobilienScout24/dns-web-scanner

positional arguments:
  TARGET                path to csv file or DNS names or URLs

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -v, --verbose         verbose operation
  -H, --html            create HTML output
  -C, --csv             create CSV output
  -w, --with-www        also scan www.TARGET for each target when reading from
                        CSV file
  -o FILE, --output FILE
                        output result to FILE
```
