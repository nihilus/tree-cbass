'''

This program interfaces with the dynamic execution trace(generated from platform-dependent instrumentation or emulation environment) and 
provides concrete values of memory and registers for concrte/symbolic execution. 
Inputs:
    -- Dynamic Trace File with fine-grained instruction level state information
 Output:
   -- Instruction address and relevant program state 
   
 * @author Nathan Li
 * 
 */

'''
import os
import struct
import logging

log = logging.getLogger('TREE')
from ctypes import *
from ctypes.util import *
import ctypes

from x86Decoder import x86Decoder, instDecode, IMMEDIATE, REGISTER,MEMORY, WINDOWS, LINUX
from x86Thread import X86Thread

Invalid, LoadImage,UnloadImage,Input,ReadMemory,WriteMemory,Execution, Snapshot, eXception = range(9)

class InstructionEncoding(object):
    def __init__(self):
        self.address = None
        self.size = None
        self.encoding = None
        self.menica = None
        
class TraceRecord(object):
    def __init__(self):
        self.recordType= Invalid
        
    def getRecordType(self):
        return self.recordType
    
class InstructionTraceRecord(TraceRecord):
    def __init__(self):
        self.recordType = Execution
        self.currentLine = None
        self.currentInstruction = None
        self.currentInstSize = None
        self.sEncoding = None
        self.currentThreadId = None
        self.currentInstSeq = 0
        self.currentReadAddr = None
        self.currentReadSize = None
        self.currentReadValue = {}
        self.currentWriteAddr = None
        self.currentWriteSize = None
        self.currentWriteValue = {}
        self.reg_value={}

    def getDebugInfo(self):
        
        sDbg = "0x%x %d 0x%x 0x%x " %(self.currentInstruction,self.currentInstSize,self.currentThreadId,self.currentInstSeq)

        if (len(self.reg_value)>0):
            sDbg = sDbg + "Reg( "
            for reg in self.reg_value:
                sDbg = sDbg + "%s=%s " %(reg,self.reg_value[reg])
            sDbg = sDbg + " ) "
        
        if(self.currentReadSize is not None):
            sDbg = sDbg + "R %d 0x%x " %(self.currentReadSize, self.currentReadAddr)
            for i in range(self.currentReadSize):
                sDbg = sDbg + "0x%x " % self.currentReadValue[i]
                
        if(self.currentWriteSize is not None):                
            sDbg = sDbg + "W %d 0x%x " %(self.currentWriteSize, self.currentWriteAddr)
            for i in range(self.currentWriteSize):
                if(self.currentWriteValue[i] !=None):
                    sDbg = sDbg + "0x%x " % self.currentWriteValue[i]
        
        sDbg = sDbg + " \n"
        return sDbg

class ExceptionTraceRecord(TraceRecord):    
    def __init__(self):
        self.recordType =  eXception
        self.currentExceptionCode = None
        self.currentExceptionAddress = None

class InputTraceRecord(TraceRecord):    
    def __init__(self):
        self.recordType = Input
        self.currentInputAddr = None
        self.currentInputSize = None
        self.inputBytes = None
        self.inputFunction = None
        self.functionCaller = None
        self.callingThread = None
        self.sequence = None
        self.inputHandle = None

class LoadImageTraceRecord(TraceRecord):    
    def __init__(self):
        self.recordType = LoadImage
        self.ImageName = None
        self.ImageSize = None
        self.LoadAddress = None
        

class IDBTraceReader(object):

    def __init__(self, trace_buf):
        self.trace_buffer = trace_buf
        self.lines = self.trace_buffer.splitlines()
        self.current_line = 0
    
    def reSet(self):
        self.current_line = 0
    
    def getNext(self):
        if(self.trace_buffer is None):
            print("Invalid trace buffer\n")
            return None

        line =  self.lines[self.current_line]
        self.current_line = self.current_line+1
        line = line.strip()
        split = line.split(" ")
        skip = 0

        while line is not None:
            log.debug(line)
            if(self.current_line >= len(self.lines)):
                return None
            tRecord = None
            if split[0] == "L":
                tRecord = self.parseImageLine(line)
                skip = 0				
                return tRecord
            elif split[0] == "I":
                tRecord = self.parseInputLine(line)
                skip = 0				
                sDbg = "TraceReader: After input %s, return tRecord" %(line)
                log.debug(sDbg)
                return tRecord
            elif split[0] == "E":
                sDbg = "TraceReader: ELine %s, return tRecord" %(line)
                log.debug(sDbg)
                tRecord = self.parseInstructionLine(line) 
                skip = 0
                return tRecord
            elif split[0] == "X":
                tRecord = self.parseExceptionLine(line)
                skip = 0
                return tRecord       
            elif split[0] == "T":
                tRecord = self.parseExceptionLine(line)
                skip = 0
                return tRecord       
            else:
                if( line=="EOF"):
                    sDbg= "EOF reached %s" %line
                    log.debug(sDbg)
                    break;
                elif skip <5:
                    skip = skip+1
                else:
                    sDbg= "Skip too many lines: STOP! %s" %line
                    log.debug(sDbg)
                    break            
            self.current_line = self.current_line+1
            line =  self.lines[self.current_line]
            line = line.strip()
            split = line.split(" ")

    def parseInputLine(self,line):
        split = line.split(" ")
        iRecord = InputTraceRecord()
        
        iRecord.currentInputAddr = int(split[1], 16)
        iRecord.currentInputSize = int(split[2], 10)
        sDbg= "Trace Input received at 0x%x for %d bytes" %(iRecord.currentInputAddr,iRecord.currentInputSize)
        #I 103e138 12 414141414141414141414141 0x63c4 0x0 wsock32_recv 0x11d110e 0x78
        # or I 103e138 12 414141414141414141414141 "old format"
        iRecord.inputBytes = split[3]
        if len(split)> 4:
            iRecord.callingThread = int(split[4],16)            
            iRecord.sequence = int(split[5],16)            
            iRecord.inputFunction = split[6]
            iRecord.functionCaller = int(split[7],16)
            iRecord.inputHandle = int(split[8],16)
        else:
            iRecord.callingThread = 0            
            iRecord.sequence = 0
            iRecord.inputFunction = "Unknown"
            iRecord.functionCaller = 0
            iRecord.inputHandle = 0
        log.debug(sDbg)
        
        return iRecord

    def parseImageLine(self, line):
        sDbg= "parsing image line: %s" % (line)
        log.debug(sDbg)

        iRecord = LoadImageTraceRecord()
        
        split = line[2:] #remoe the L identifier, then split with comma
        #csplit = split.split(",") # default is space, which may have problem with Windows Path
        csplit = split.split() # default is space, which may have problem with Windows Path
        # Image load, extrac the name from the fullpath
        if len(csplit)>2:               
            sImageName = csplit[0].rsplit("\\",1)
            if len(sImageName)>1:
                iRecord.ImageName = (csplit[0].rsplit("\\",1))[1]
            else:
                iRecord.ImageName = sImageName
            sDbg= "parsing image: %s" % (iRecord.ImageName)
            log.debug(sDbg)
                    
            iRecord.LoadAddress = int(csplit[1], 16)
            iRecord.ImageSize = int(csplit[2], 16)
       
        return iRecord

    def parseExceptionLine(self,line):
        split = line.split(" ")
        iRecord = ExceptionTraceRecord()

        iRecord.currentExceptionAddress = int(split[1], 16)        
        iRecord.currentExceptionCode = int(split[2], 16)

        sDbg= "Text Tracer: Exception happened at 0x%x with exception code %x" %(iRecord.currentExceptionAddress,iRecord.currentExceptionCode)
        log.debug(sDbg)
        print("%s" %sDbg)
        
        return iRecord
                            
        
    def parseInstructionLine(self,line):
        
        iRecord = InstructionTraceRecord()
        
        line = line.strip()
        split = line.split(" ")
        nParts = len(split)
        if split[0] == "E":
            #"Located Instruction header:"
            iRecord.currentInstruction = int(split[1],16)
            iRecord.currentInstSize = int(split[2],16)
            iRecord.sEncoding = split[3]
            iRecord.currentThreadId = int(split[4],16)
            iRecord.currentInstSeq = int(split[5],16)
            sDbg= "Addr=0x%x, Thread=%x, Seq=%d" %(iRecord.currentInstruction,iRecord.currentThreadId,iRecord.currentInstSeq)
            log.debug(sDbg)
            #print("%s" %sDbg)
            
            if(nParts<=6):
                return iRecord
            i=6                       
            if(split[i] == "Reg("):
                #read register name and value pair
                i=i+1
                while (split[i] != ")"):
                    #read concrete values from trace
                    reg_value_pair=(split[i]).split("=")
                    regname = reg_value_pair[0].lower()
                    regvalue = int(reg_value_pair[1],16)
                    iRecord.reg_value[regname] = regvalue
                    sDbg = "regname=%s, regvalue=0x%x" %(regname,iRecord.reg_value[regname])
                    log.debug(sDbg)
                    i= i+1
                i=i+1
            if(nParts-i>=3):
                #print("R: nParts=%d, i=%d split[i+1]=%s " %(nParts, i, split[i+1]))
                if(split[i] == "R"):
                    sSize = split[i+1].lstrip()
                    iRecord.currentReadSize = int(sSize.lstrip(), 10) # in byte                
                    iRecord.currentReadAddr = int(split[i+2], 16)

                    memBytes = (split[i+3]).split("_")
                    sDbg= "Read %d bytes at 0x%x: " %(iRecord.currentReadSize,iRecord.currentReadAddr)
                    log.debug(sDbg)
                    
                    if(memBytes[0]!='X'):
                        j =0;
                        #iRecord.currentReadValue = c_byte*iRecord.currentReadSize
                        #readBytes = iRecord.currentReadValue()
                        while j<iRecord.currentReadSize:
                            #readBytes[j] = int(memBytes[j],16)
                            iRecord.currentReadValue[j] = int(memBytes[j],16)
                            #sDbg= "Offset:%d,Value=0x%x" %(j,readBytes[j])
                            #log.debug(sDbg)
                        #TODO: validate if this matches exec simulation
                            j=j+1               
                        i=i+3
                    else:
                        i = i+2
                    
            if(nParts-i>=3):                    
                head = split[i+1].lstrip()
                if(head== "W"):
                    sSize = split[i+2].lstrip()    
                    iRecord.currentWriteSize = int(sSize, 10) # in byte                
                    iRecord.currentWriteAddr = int(split[i+3], 16)
                    sDbg = "Write %d bytes at 0x%x: " %(iRecord.currentWriteSize,iRecord.currentWriteAddr)
                    log.debug(sDbg)
                    #print("%s" %sDbg)

        return iRecord


        