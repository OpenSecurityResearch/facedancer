#!/usr/bin/env python
#
# This program takes a VMWare USB log, and parses the
# data sent by a specific endpoint 
#  
# brad.antoniewicz@foundstone.org
#

'''
Useful one liners:

grep -B 6 "42 ad 00 4a" ~/navigo/vmware_omnikey_navigo_successauth.log | sed -e '/Up/d' -e '/Down/d' -e 's/^.*USBIO:  //' -e 's/^[0-9]\{3\}: //' -e 's/\(.\)\{17\}$//g' | tr -d '\n' | sed -e 's/--/\n/g' | tr 'a-z' 'A-Z' | sort

 grep -A 6 "00 4a 00" ~/navigo/vmware_omnikey_navigo_successauth.log | sed -e 's/^.*USBIO:  //' -e /2013/d -e 's/^[0-9]\{3\}: //' -e 's/\(.\)\{17\}$//g' | tr -d '\n' |  sed -e 's/--/\n/g'

'''



import re;
import sys;
import getopt;



def parseLine(line,responseList):
    #print line
    matchObj = re.match(r'.*\d{3}: ((?:(?:[0-9a-f]{2}) ){1,}).{1,}', line, re.M);
    if matchObj:
        bytes = str(matchObj.group(1)).split(" ");
        for byte in bytes:
            if byte != "":
                responseList.append(byte);	

def printVar(master):
    count = 0;
    strCount = 0;
    for responseList in master: 
        print "respStr_%04d\t= [\t"%(strCount),;
        for i in responseList[:-1]:
            if count == 7:
                print "0x%s,"%i;
                print "\t\t\t",
                count = 0;
            else:
                print "0x%s, "%(i),;
                count += 1;
        print "0x%s"%responseList[-1];
        print "\n\t\t\t];\n";
        count=0;
        strCount += 1;

def printLine(master):
    for responseList in master:
        for i in responseList[:-1]:
            print " %s"%i,;
        print " %s"%responseList[-1];

def findDups(master):
    checked = [];
    for e in master:
        if e not in checked:
            checked.append(e);
    return checked;


def usage():
    print "\nSet the following settings within the .vmx file associated with your VM:"
    print " \t#";
    print " \t# START USB Debugging Options";
    print " \t# as per http://vusb-analyzer.sourceforge.net/tutorial.html";
    print " \t#";
    print " \t.encoding = \"windows-1252\"";
    print " \t";
    print " \tmonitor = \"debug\"";
    print " \tusb.analyzer.enable = TRUE";
    print " \tusb.analyzer.maxLine = 8192";
    print " \tmouse.vusb.enable = FALSE";
    print " \t";
    print " \t#";
    print " \t# END USB Debugging Options";
    print " \t#";
    print " \t#";
    print "\nUsage:"  
    print "\t-f [file]\t VMWare Log File (USBIO)";
    print "\t-e [EP ADDR]\t Endpoint 1 (Host - Implies USBIO Down - No work)";
    print "\t-p [EP ADDR]\t Endpoint 2 (Device)";
    print "\t-i \t Output python importable variables";
    print "\t-s \t Output hex strings";
    print "\t-r \t Remove duplicates";
    print "Example:" 
    print "\t" + sys.argv[0] + " 84 vmware.log";
    print "\n";
    sys.exit(-1);

'''
main
'''

endPoint1 = endPoint2 = output = remDups = 0;
vmLogFile = None;


print "VMWare USBIO Log Parser"
print "Creates importable Python strings"
print "by brad.antoniewicz@foundstone.com"
print "------------------------------------------"

try:
    opts,args = getopt.getopt(sys.argv[1:], "hf:e:p:rsi", []);
except getopt.GetoptError:
    usage(sys.argv[0]);

for o,a in opts:
    if o == "-h":
        usage();
    if o == "-f":
        vmLogFile = a;
    if o == "-e":
        endPoint1 = a;
    if o == "-p":
        endPoint2 = a;
    if o == "-i":
        output = 0; # Python Output
    if o == "-s":
        output = 1; # Hex output
    if o == "-r":
        remDups = 1;
        

if vmLogFile == None or ( endPoint2 == 0 and endPoint1 == 0):
    usage();

numLinesAfter = 0;
#strCount = 0;
getState = 0; 

#ep1RespList = []; # Usually the host
#ep2RespList = []; # Usually the device

epRespList = [];
responseListMaster = [];
responseListFinal = [];

epSearchStr=None;

if endPoint1 != 0: 
    print "[+] Search for Endpoint1 [" + endPoint1 + "] within " + vmLogFile;
    ep1SearchStr = "USBIO: Down.*endpt="+endPoint1+".* datalen=([0-9]{1,}) .*";
    epSearchStr = ep1SearchStr;
elif endPoint2 != 0:
    print "[+] Search for Endpoint2 [" + endPoint2 + "] within " + vmLogFile;
    ep2SearchStr = "USBIO: Up.*endpt="+endPoint2+".* datalen=([0-9]{1,}) .*";
    epSearchStr = ep2SearchStr;



inputFile = open(vmLogFile, 'r');

for line in inputFile:
    if numLinesAfter == 0:
        matchObj = re.search(r''+epSearchStr+'', line, re.M);
        if matchObj:
            packetLen =  int(matchObj.group(1));
            if packetLen%16 == 0:
                numLinesAfter = packetLen/16;
            else:
                numLinesAfter = (packetLen/16)+1;
    elif numLinesAfter > 0:
        parseLine(line,epRespList);
        numLinesAfter -= 1;
        if numLinesAfter == 0:
            responseListMaster.append(epRespList[:]);
            epRespList[:] = []; # Clears

inputFile.close();

if remDups:
   responseListFinal = findDups(responseListMaster); 
else:
   responseListFinal = responseListMaster;

if output == 0:
    printVar(responseListFinal);
elif output == 1:
    printLine(responseListFinal);

