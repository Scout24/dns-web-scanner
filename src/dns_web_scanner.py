#!/usr/bin/python
# encoding: utf-8
'''
Read DNS names or URLs from CSV files or command line. The name will be checked for
a valid DNS response (CNAME or A) and a working web server on port 80. HTTP
and (I)FRAME redirects will be followed and checked.

(I)FRAME redirects is something we want to get rid off, so they count as an error.

CSV files are ;-separated and the first line (headers) is skipped. Only the first element
from the CSV file is used and should be a host or URL without the http:// prefix.
'''

import sys
import os
import traceback
import csv
import urllib2
import urlparse
import httplib
import socket
from ADNS import adns
from Cheetah.Template import Template

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

__all__ = []
__version__ = 2

PROFILE = 0

HTML_TEMPLATE="""<!DOCTYPE HTML>
<html>
#raw
<!-- DataTables CSS -->
<link rel="stylesheet" type="text/css" href="http://ajax.aspnetcdn.com/ajax/jquery.dataTables/1.9.4/css/jquery.dataTables.css">
 
<!-- jQuery -->
<script type="text/javascript" charset="utf8" src="http://ajax.aspnetcdn.com/ajax/jQuery/jquery-1.9.1.min.js"></script>
 
<!-- DataTables -->
<script type="text/javascript" charset="utf8" src="http://ajax.aspnetcdn.com/ajax/jquery.dataTables/1.9.4/jquery.dataTables.min.js"></script>

<style type="text/css">
.OK {
    color: green;
    font-weight: bold;
}
.BAD {
    color: red;
    font-weight: bold;
}
table,th,td {
    border: 1px solid black;
}
td {
    vertical-align:top;
    padding:2px;
}
table {
    border-collapse:collapse;
    max-width:100%%;
}
thead {
    border-bottom: 1px double black;
    background-color: lightgrey;
}

</style>
<script type="text/javascript">
$(document).ready(function(){
  $('#content').dataTable( {
    "bPaginate": false
      });
});
</script>
<body>
<table id="content">
<thead>
<tr><th>Target</th><th>Result</th><th>Details</th></tr>
</thead>
<tbody>
#end raw
#for $result in $results
<tr><td>$result.target</td><td class="$result.good_text">$result.good_text</td><td>#echo ", ".join($result.steps)#</td></tr>
#end for
</tbody>
</table>
<br/>
<hr>
<em>Created by <a href="http://github.com/ImmobilienScout24/dns-web-scanner">dns-web-scanner</a> Version %s</em>
</body>
</html>""" % (__version__)

class DnsWebScannerError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(DnsWebScannerError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

class DnsWebScannerResult(object):
    def __init__(self, target):
        #print >>sys.stderr,"New Result %s" % id(self)
        self.__target = target
        self.__steps = []
        self.__good = False
    
    def fail_with(self, step):
        self.__good = False
        self.add(step)

    def add(self, step):
        #print >>sys.stderr,"Adding %s to %s" % (step,id(self))
        self.__steps.append(step)
    
    def success(self):
        self.__good = True
    
    def good(self):
        return self.__good
    
    def good_text(self):
        return ("BAD","OK")[self.__good]

    def steps(self):
        return self.__steps
    
    def target(self):
        return self.__target

    def __str__(self):
        #print >>sys.stderr,"Steps:",self.__steps
        return "\n ".join([self.__target + " " + self.good_text() ] + self.__steps)

class DnsWebScanner(object):
    
    print_output = sys.stdout

    args = None
    
    def web_analyze(self, analyze_url, result):
        """ Analyze URL (must be http:// URL) and follow HTTP and (I)FRAME redirects.
        
        Returns DnsWebScannerResult object """

        #print >>sys.stderr,"web_analyze %s" % analyze_url
        (scheme, netloc, path, query, fragment) = urlparse.urlsplit(analyze_url)
        if path is "":
            path = "/"
        conn = httplib.HTTPConnection(netloc, timeout=3)
        if query is not "":
            path += "?" + query
        try:
            conn.request("GET", path)
            response = conn.getresponse()
        except socket.timeout:
            result.fail_with("CONNECT TIMEOUT after 3 seconds")
        except IOError as e:
            result.fail_with("IOERROR %s" % e.strerror)
        else:
            if response.status == 200:
                body = response.read(200)
                if body.find("Sorry, no Host found") > -1:
                    result.fail_with("INVALID REDIRECTOR")
                elif body.find("frame") > -1:
                    result.fail_with("INVALID FRAME REDIRECT")
                else:
                    result.success()
            elif response.status >= 300 and response.status < 400:
                newlocation = response.getheader("Location")
                if newlocation is None:
                    result.fail_with("INVALID REDIRECT %s WITHOUT LOCATION" % response.status)
                elif analyze_url == newlocation:
                    result.fail_with("INVALID REDIRECT %s LOOP" % response.status)
                else:
                    result.add("REDIRECT %s %s" % (response.status, newlocation))
                    result = self.web_analyze(urlparse.urljoin(analyze_url, newlocation), result)
            else:
                result.fail_with("ERROR %s %s" % (response.status, response.reason))
        return result
    
    def canonical_url(self, inurl,prefix=None):
        (scheme, netloc, path, query, fragment) = urlparse.urlsplit(inurl)
        if scheme is "":
            scheme = "http"
        if netloc is "" and path is not "":
            netloc = path
            path = "/"
        if prefix is not None:
            netloc = prefix + "." + netloc # TODO: Deal with user:pass@netloc situation
        return urlparse.urlunsplit((scheme, netloc, path, query, fragment))

    def process_target(self, target,prefix=None):
        """ Process target which can be a plain host or a URL.
        
        Will do DNS and Web checks and return a DnsWebScannerResult object"""
        #print >>sys.stderr,"process_target %s" % target
        canonical_url = self.canonical_url(target,prefix)
        result = DnsWebScannerResult(canonical_url)
        if self.args.verbose:
            print >>sys.stderr,"Processing %s" % canonical_url,
        (scheme, netloc, path, query, fragment) = urlparse.urlsplit(canonical_url)
        host = netloc.split(":")[0]
        (status, cname, expires, answer) = self.dns.synchronous(host, adns.rr.A)
        # status definitions found in http://www.chiark.greenend.org.uk/~ian/adns/adns.h.txt
        if status == adns.status.prohibitedcname:
            # need to do another query
            (status, dummy, expires, answer) = self.dns.synchronous(cname, adns.rr.A)
        if status == adns.status.ok:
            if cname is not None:
                result.add("ALIAS %s" % cname)
            result.add("ADDRESS %s" % " ".join(answer))
            result = self.web_analyze(canonical_url, result)

        elif status == adns.status.nxdomain or status == adns.status.nodata:
            result.fail_with("RESOLVED NODATA %s" % host)
        elif status == adns.status.rcodeservfail:
            result.fail_with("RESOLVER SERVER_FAILURE %s" % host)
        elif status == adns.status.timeout:
            result.fail_with("RESOLVER TIMEOUT %s" % host)
        else:
            raise DnsWebScannerError('DNS Lookup of "%s" failed with adns error "%s"\n%s' % (host, status, (cname, answer)))

        if self.args.verbose:
            print >>sys.stderr,result.good_text()
        return result
        
    def process_csv_file(self, csvfile):
        """ Read CSV file (;-separated with column headers) and process each target.
        
        Returns a list of DnsWebScannerResult objects"""
        results = []
        with open(csvfile, "rb") as f:
            reader = csv.reader(f, delimiter=";")
            try:
                reader.next()
                for row in reader:
                    results.append(self.process_target(row[0]))
                    if self.args.with_www:
                        results.append(self.process_target(row[0],"www"))
            except csv.Error as e:
                sys.exit('file %s, line %d: %s' % (csvfile, reader.line_num, e))
        
        return results
    
    def __init__(self, argv=None):  # IGNORE:C0111
        '''Command line options.'''

        if argv is None:
            argv = sys.argv
        else:
            sys.argv.extend(argv)
    
        program_name = os.path.basename(sys.argv[0])
        program_version = "v%s" % __version__
        program_version_message = '%%(prog)s %s' % program_version
        program_shortdesc = __import__('__main__').__doc__
        program_description = '''%s

Created by Schlomo Schapiro
Copyright 2013 ImmobilienScout24. All rights reserved.

Licensed under the GNU General Public License
http://www.gnu.org/licenses/gpl.html

Homepage: http://github.com/ImmobilienScout24/dns-web-scanner
''' % program_shortdesc
    
        try:
            # Setup argument parser
            parser = ArgumentParser(description=program_description, formatter_class=RawDescriptionHelpFormatter)
            parser.add_argument('-V', '--version', action='version', version=program_version_message)
            parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="verbose operation", default=False)
            group = parser.add_mutually_exclusive_group()
            group.add_argument("-H", "--html", action="store_true", dest="html", help="create HTML output", default=False)
            group.add_argument("-C", "--csv", action="store_true", dest="csv", help="create CSV output", default=False)
            parser.add_argument("-w", "--with-www", action="store_true", dest="with_www", help="also scan www.TARGET for each target when reading from CSV file", default=False)
            parser.add_argument("-o", "--output", action="store", dest="output", metavar="FILE", help="output result to FILE", default=None)
            parser.add_argument(dest="targets", help="path to csv file or DNS names or URLs", metavar="TARGET", nargs="+")
            
            # Process arguments
            self.args = parser.parse_args()
            if self.args.output is not None:
                self.print_output = open(self.args.output, "wb")
            
            # initialize resolver
            self.dns = adns.init();

        except KeyboardInterrupt:
            ### handle keyboard interrupt ###
            return 0
        except Exception, e:
            raise(e)

    def run(self):
        try:
            results = []      
            for target in self.args.targets:
                if os.path.isfile(target):
                    results.extend(self.process_csv_file(target))
                else:
                    results.append(self.process_target(target))
            if self.args.html:
                print >>self.print_output,Template(HTML_TEMPLATE,searchList=[{"results":results}])
            elif self.args.csv:
                print >>self.print_output,"Target;Result;Details"
                for result in results:
                    print >>self.print_output,";".join([result.target(),result.good_text()] + result.steps())
                pass
            else:
                for result in results:
                    print >>self.print_output,result
            return 0
        except KeyboardInterrupt:
            ### handle keyboard interrupt ###
            return 0
        except Exception:
            sys.stderr.write("An unexpected Exception happened:")
            traceback.print_exc()
            return 2
    
if __name__ == "__main__":
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = '_profile.txt'
        cProfile.run('DnsWebScanner().run()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    else:
        sys.exit(DnsWebScanner().run())
