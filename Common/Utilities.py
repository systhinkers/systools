import threading
import os
import sys
import subprocess
import logging
import ConfigParser
import time
import tarfile
import os.path
import json
import xml.etree.ElementTree as ET
import re
import yaml
import xmltodict 
import socket
import struct
from intspan import intspan
import urllib
import urllib2
import shutil

FORMAT = '[%(levelname)s][%(asctime)-15s][%(module)s.%(funcName)s][%(lineno)d] - %(message)s'

def pretty_print(data):
    """
    
    """
    return json.dumps(data, indent=4, sort_keys=True)

def rangify(nodes):
    """
    rangify hosts list
    
    Parameters
    ----------
    
    nodes: list
    
    """
    data_array = []
    info_hash = dict()
    for node in nodes:
        match = re.match('^([a-zA-Z]+\d+[a-zA-Z]+|[a-zA-Z]+)(\d+)(\..*)$', node)
        if match:
            (prefix,number,suffix) = match.groups()
            if suffix not in info_hash.keys(): info_hash[suffix] = dict()
            if prefix not in info_hash[suffix].keys(): info_hash[suffix][prefix] = dict()
            info_hash[suffix][prefix][number] = 1
        
        if re.match('.*\[.*\].*', node):
            logging.warn(node+" : already in range")
            data_array.append(node)

    for suffix in sorted(info_hash.keys()):
        for prefix in sorted(info_hash[suffix].keys()): 
            length = 0
            for num in info_hash[suffix][prefix].keys():
                length = len(str(num))
            ints = []
            ints = [int(x) for x in info_hash[suffix][prefix].keys()]
            ints.sort()
            min = -1
            max = 0
            last = -1
            for i in ints:
                if min == -1 or i < min:
                    min = i
                else:
                    if last > -1 and i != int(last + 1):
                        if min == max:
                            data_array.append("%s%s%s" %(prefix,str(max).zfill(length),suffix))
                        else:
                            data_array.append("%s[%s-%s]%s" %(prefix,str(min).zfill(length),str(max).zfill(length),suffix))
                        min = i
                        max = i
                if i > max: max = i
                last = i
            if min == max:
                data_array.append("%s%s%s" %(prefix,str(max).zfill(length),suffix))
            else:
                data_array.append("%s[%s-%s]%s" %(prefix,str(min).zfill(length),str(max).zfill(length),suffix))
    return data_array

def derangify(nodes):
    data_array = []
    for node in nodes:
        match = re.match('(.*)\[(.*)\](\..*)', node)
        if match:
            (prefix,n,suffix) = match.groups()
            length = 0
            #for num in intspan(nrange):
            #    if length < len(str(num)): length = len(str(num))
            for nrange in n.split(','):
                if re.match('.*\-.*',nrange):
                    (r1,r2) = nrange.split('-')
                    length = len(str(r2))
            #else:
            #    length = len(str(nrange))
            #print "%s : %d"%(nrange,length)    
                for num in intspan(nrange):
                    data_array.append("%s%s%s" %(prefix,str(num).zfill(length),suffix))
        else:
            data_array.append(node)

    return data_array

def getLogger(name, level=logging.INFO, logfile=''):
    
    console = logging.StreamHandler(sys.stdout)
    if logfile != '':
        logging.basicConfig(format=FORMAT, filename=logfile, level=level)
        console.setLevel(level)
        formatter = logging.Formatter(FORMAT)
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)
    else:
        logging.basicConfig(format=FORMAT, level=level)
    logger = logging.getLogger(name)

def byteConverter(size, unit, precision=2):
    suffixes=['B','KB','MB','GB','TB','PB']
    suffixIndex = 0
    while suffixIndex < 5:
        suffixIndex += 1
        size = size/1024.0
        if unit == suffixes[suffixIndex]:
            break
    return "%.*f"%(precision,size)

def mergeFiles(path,files,filename):
    logging.debug("Start")
    filename += "."+str(int(time.time()))
    with open(path+"/../"+filename, 'w') as outfile:
        for fname in files:
            if os.path.isfile(path+"/"+fname):
                with open(path+"/"+fname) as infile:
                    for line in infile:
                        outfile.write(line)
    logging.debug("Stop")
    return path+"/../"+filename

def uncompressFile(filename, extract_path='.'):
    tar = tarfile.open(filename, 'r')
    for item in tar:
        tar.extract(item, extract_path)

def compressFile(filename):
    logging.debug("Start")
    tar = tarfile.open(filename+".tgz", "w:gz")
    tar.add(filename)
    tar.close()
    os.remove(filename)
    logging.debug("Stop")
    return filename+".tgz"

def compressDir(path, filename):
    logging.debug("Start")
    tar = tarfile.open(path+filename+".tgz", "w:gz")
    tar.add(path+filename, arcname=filename)
    tar.close()
    shutil.rmtree(path+filename)
    logging.debug("Stop")
    return path+".tgz"

def ip2host(ip):
    if isinstance(ip, list):
        hosts = []
        for addr in ip:
            hosts.append(socket.gethostbyaddr(addr)[0])
        return hosts
    else:
        return socket.gethostbyaddr(ip)[0]

def host2ip(host):
    if isinstance(host, list):
        ips = []
        for node in host:
            ips.append(socket.gethostbyname(node)[0])
        return ips
    else:
        return socket.gethostbyname(node)[0]
        

def unixSocket(host, port, command):
    data = ''
    try:
        socket.setdefaulttimeout(10)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        client.send(command)
        raw_msglen = recvall(client, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        logging.info("Message length for %s:%s, command : %s : %i bytes"% (host, port, command, msglen))
        data = recvall(client, msglen)

    except OSError as err:
        raise OSError(err)
    else:
        client.close()
        return data
    
def recvall(client, n):
    data = ''
    while len(data) < n:
        packet = client.recv(n - len(data))
        if not packet:
            break
        data += packet
    return data

def runCommand(command, blocking=True, retry=1, dryrun=False):
   logging.debug("Start runCommand")
   logging.debug("Command : "+command)
   retval = 0
   output = ''
   if dryrun:
      logging.info("Dryrun enabled. skipping....")
   else:
      while retry:
         p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
         if blocking:
            output = "".join(p.stdout.readlines())
            logging.debug("================================================================")
            logging.debug(output)
            logging.debug("================================================================")
            retval = p.wait()
            if retval:
               logging.warn("command failed")
               retry -= 1
            else:
               retry = 0
   logging.debug("Stop runCommand")
   return retval, output

def runCommandTimer(command, retry=1, dryrun=False, timeout=60):
    retval = 2
    output = 'Failed to run'
    logging.debug("Command : "+command)
    if not dryrun:
       start = datetime.datetime.now()
       p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
       logging.debug("Pid of spawned process : %d"%p.pid)
       try:
          while p.poll() is None:
             time.sleep(0.1)
             now = datetime.datetime.now()
             if (now - start).seconds> timeout:
                os.kill(p.pid, signal.SIGKILL)
                os.waitpid(-1, os.WNOHANG)
       except Exception as err:
          logging.debug("Pid killed doesnt exist %s"%err)
       else:
          retval = 0
          output = p.stdout.read()
    else:
       logging.info("Dryrun enabled : %s"%command)
    return retval, output

def readYaml(filename):

    info_hash = dict()
    with open(filename, 'r') as stream:
        try:
            info_hash = yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc)
        else:
            return info_hash
    return None

def grep(pattern,my_list):
    e = re.compile(pattern)
    return [item for item in my_list if e.match(item)]

def isJSON(jsonstring):
  json_object = dict()
  try:
      json_object = json.loads(jsonstring)
  except ValueError, e:
      return False, json_object
  return True, json_object

def xmlFile(filename):
  tree = ET.parse(filename)
  xmldict = tree.getroot()
  return tree, xmldict

def xmlString(data):
    return xmltodict.parse(data)

def getFileData(filename):
   f = open(filename, 'r')
   data = f.read()
   f.close()
   return data
