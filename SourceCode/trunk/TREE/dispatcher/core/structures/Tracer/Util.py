#!/usr/bin/env python

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