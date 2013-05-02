#!/usr/bin/env python
import configparser

dbgFlag = False

def Print(string):
    if dbgFlag:
        print string

class ConfigReader:
    def __init__(self,path):
        self.path = path
    
    def Read():
        global dbgFlag
        config = configparser.ConfigParser()
        config.read(path)
        print(config['DEBUGGING']['MESSAGE'])
        if config['DEBUGGING']['MESSAGE']=="On":
            dbgFlag = True
        else:
            dbgFlag = False
        
    """
    incomplete - needs implementation
    def Update():
        config['DEFAULT']['path'] = '/var/shared/'    # update
        config['DEFAULT']['default_message'] = 'Hey! help me!!'   # create
    
    def Write():
        with open('FILE.INI', 'w') as configfile:    # save
            config.write(configfile)
    """
    
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