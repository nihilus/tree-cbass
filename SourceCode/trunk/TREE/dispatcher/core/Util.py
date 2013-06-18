#!/usr/bin/env python
import ConfigParser
from dispatcher.core.DebugPrint import DebugPrint
import itertools
import os
import re

class ConfigReader:
    def __init__(self):
        self.version = None
        self.logging = None
        self.debugging = None
        self.traceFile = None
        self.configFile = None
        
    def Read(self,path):

        config = ConfigParser.ConfigParser()
        config.read(path)
        _dbgPrint = DebugPrint()
        """
        print config.get('DEFAULT','DebugMessageOn')
        print config.get('DEFAULT','Version')
        print config.get('DEFAULT','Logging')
        print config.get('DEFAULT','Debugging')
        """
        if config.get('DEFAULT','DebugMessageOn')=="True":
            _dbgPrint.dbgFlag = True
           # print "dbgFlag set to True"
        else:
            _dbgPrint.dbgFlag = False
           # print "dbgFlag set to False"
            
        self.version = config.get('DEFAULT','Version')
        self.logging = config.get('DEFAULT','Logging') == "True"
        self.debugging = config.get('DEFAULT','Debugging') == "True"
        self.traceFile = config.get('DEFAULT','Trace_File')
        self.configFile = config.get('DEFAULT','Config_File')

def toHex(s):
    
    if s is None:
        return ""
    
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    
    return reduce(lambda x,y:x+y, lst)

def Read(addr,size):
    import idaapi
    import struct
    
    byteArray = []
    count = 0

    while True:
        byte= idaapi.dbg_read_memory(addr,size)

        count = count+1
        nullTest= struct.unpack("B",byte[0])
        
        if nullTest[0]==0:
            break;
        else:
            byteArray.append(byte[0])
            addr = addr+size
        
    #print byteArray
    
    return byteArray

def GetData(index):
    import idc
    
    esp = idc.GetRegValue("ESP")
    return idc.DbgDword(esp+index)

def unique_file_name(file):
    """
    Append a counter to the end of file name if such file allready exist.
    """
    if not os.path.isfile(file):
        # do nothing if such file doesn exists
        return file
    # test if file has extension:
    if re.match('.+\.[a-zA-Z0-9]+$', os.path.basename(file)):
        # yes: append counter before file extension.
        name_func = \
            lambda f, i: re.sub('(\.[a-zA-Z0-9]+)$', '_%i\\1' % i, f)
    else:
        # filename has no extension, append counter to the file end
        name_func = \
            lambda f, i: ''.join([f, '_%i' % i])
    for new_file_name in \
        (name_func(file, i) for i in itertools.count(1)):
        if not os.path.exists(new_file_name):
            return new_file_name

if __name__ == '__main__':
    configReader = ConfigReader("C:\\TREE\\settings.ini")
    configReader.Read()