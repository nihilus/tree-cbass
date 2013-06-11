#!/usr/bin/env python
import ConfigParser
from dispatcher.core.DebugPrint import DebugPrint

class ConfigReader:
    def __init__(self):
        self.version = None
        self.logging = None
        self.debugging = None
        self.traceFile = None
        
    def Read(self,path):

        config = ConfigParser.ConfigParser()
        config.read(path)
        _dbgPrint = DebugPrint()
        print config.get('DEFAULT','DebugMessageOn')
        print config.get('DEFAULT','Version')
        print config.get('DEFAULT','Logging')
        print config.get('DEFAULT','Debugging')
        
        if config.get('DEFAULT','DebugMessageOn')=="True":
            _dbgPrint.dbgFlag = True
            print "dbgFlag set to True"
        else:
            _dbgPrint.dbgFlag = False
            print "dbgFlag set to False"
            
        self.version = config.get('DEFAULT','Version')
        self.logging = config.get('DEFAULT','Logging')
        self.debugging = config.get('DEFAULT','Debugging')
        self.traceFile = config.get('DEFAULT','Trace_File')

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

if __name__ == '__main__':
    configReader = ConfigReader("C:\\TREE\\settings.ini")
    configReader.Read()