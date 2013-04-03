'''

This program interfaces with the dynamic execution trace(generated from platform-dependent instrumentation or emulation environment) and 
provide concrete values of memory and registers for concrte/symbolic execution. 
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

log = logging.getLogger('CIDATA')
from ctypes import *
from ctypes.util import *
import ctypes

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
        self.currentReadValue = None
        self.currentWriteAddr = None
        self.currentWriteSize = None
        self.currentWriteValue = None
        self.reg_value={}

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

class LoadImageTraceRecord(TraceRecord):    
    def __init__(self):
        self.recordType = LoadImage
        self.ImageName = None
        self.ImageSize = None
        self.LoadAddress = None
        
        
class CIDATraceReader(object):
    def __init__(self, trace_file):
        self.exe_trace = trace_file
            
    def loadImage(self, imageName, loadOffset, lowAddress, highAddress):
#        self.images[imageName] = BinImage(loadOffset, lowAddress,highAddress)
        self.currentImage = imageName

    def getCurrentImage(self):
        return self.currentImage
              
    def unloadImage(self, mod_id, mod_path):
        pass
 
    def getNext(self):
        pass
    
    def parseInput(self, line):
        pass

    def parseInstruction(self, line):
        pass
 
    def parseImageLine(self, line):
        pass
   
    def parseException(self,line):
        pass
        
        
class CIDATextTraceReader(CIDATraceReader):

    def __init__(self, trace_file):
        super(CIDATextTraceReader,self).__init__(trace_file)
        self.trace_fd = open(self.exe_trace, 'r') 
        
    def getNext(self):
        if(self.trace_fd is None):
            print("Invalid trace file\n")
            return None
        
        line = self.trace_fd.readline()        
        sDbg = "TextTraceReader: %sline:%s" %("\n\n",line)
        log.debug(sDbg)
        
        if line==None:
            print ("No more line. Quit!\n")
            return None

        line = line.strip()
        split = line.split(" ")
        skip = 0

        while line is not None:
            log.debug(line)
            tRecord = None
            if split[0] == "L":
                tRecord = self.parseImageLine(line)
                skip = 0				
                return tRecord
            elif split[0] == "I":
                tRecord = self.parseInputLine(line)
                skip = 0				
                sDbg = "TextTraceReader: After input %s, return tRecord" %(line)
                log.debug(sDbg)
                return tRecord
            elif split[0] == "E":
                sDbg = "TextTraceReader: ELine %s, return tRecord" %(line)
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
            line = self.trace_fd.readline()
            line = line.strip()
            split = line.split(" ")

    def parseInputLine(self,line):
        split = line.split(" ")
        iRecord = InputTraceRecord()
        
        iRecord.currentInputAddr = int(split[1], 16)
        iRecord.currentInputSize = int(split[2], 10)
        sDbg= "Text Trace Input received at 0x%x for %d bytes" %(iRecord.currentInputAddr,iRecord.currentInputSize)
        log.debug(sDbg)
        
        return iRecord

    def parseImageLine(self, line):
        sDbg= "parsing image line: %s" % (line)
        log.debug(sDbg)

        iRecord = LoadImageTraceRecord()
        
        split = line[2:] #remoe the L identifier, then split with comma
        csplit = split.split()
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
                    
                    j =0;
                    iRecord.currentReadValue = c_byte*iRecord.currentReadSize
                    readBytes = iRecord.currentReadValue()
                    while j<iRecord.currentReadSize:
                        readBytes[j] = int(memBytes[j],16)
                        sDbg= "Offset:%d,Value=0x%x" %(j,readBytes[j])
                        log.debug(sDbg)
                        #TODO: validate if this matches exec simulation
                        j=j+1               
                    i=i+3
                    
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

class CIDAPinTraceReader(CIDATraceReader):
    def __init__(self, trace_file, instruction_file):
        super(CIDAPinTraceReader,self).__init__(trace_file)
        self.instruction_file = instruction_file
        self.inst_fd = open(self.instruction_file, 'r')
        self.trace_fd = open(self.exe_trace, 'r') 
        self.ins2Encoding={}

        line = self.inst_fd.readline()        
        
        while line is not None:
            line = line.strip()
            split = line.split(" ")
            
            if(len(split)<2):
                break;
            instEncoding = InstructionEncoding()
            instEncoding.address =int(split[0],16)
            instEncoding.size = int(split[1])
            instEncoding.encoding = split[2]
            self.ins2Encoding[instEncoding.address]=instEncoding

            line = self.inst_fd.readline()        
        
        '''                
        for addr in self.ins2Encoding:
            print("inst_addr=0x%x, size=%d, encoding=%s" %(self.ins2Encoding[addr].address,self.ins2Encoding[addr].size,self.ins2Encoding[addr].encoding)) 
        '''
        self.inst_fd.close()
        
    def getNext(self):
        if(self.trace_fd is None):
            print("Invalid trace file\n")
            return None
        
        line = self.trace_fd.readline()        
        sDbg = "TextTraceReader: %sline:%s" %("\n",line)
        log.debug(sDbg)
        
        if line==None:
            print ("No more line. Quit!\n")
            return None

        line = line.strip()
        split = line.split(" ")
        skip = 0
        while line is not None:
            tRecord = None
            if split[0] == "L":
                tRecord = self.parseImageLine(line) 
                skip = 0
                return tRecord
            elif split[0] == "I":
                tRecord = self.parseInputLine(line)
                skip = 0
                return tRecord
            elif split[0] == "E":
                tRecord = self.parseInstructionLine(line) 
                skip = 0
                return tRecord
            elif split[0] == "X":
                tRecord = self.parseExceptionLine(line)      
                skip = 0
                return tRecord       
            else:
                if( line=="EOF"):
                    sDbg= "EOF reached %s" %line
                    log.debug(sDbg)
                    break;
                elif(skip > 5):
                    break
                else:
                    skip= skip+1
                    sDbg= "PinParser: Skip the current line: %s" %line
                    log.debug(sDbg)
            
            line = self.trace_fd.readline()
            line = line.strip()
            split = line.split(" ")

    def parseInputLine(self,line):
        split = line.split(" ")
        iRecord = InputTraceRecord()
        
        iRecord.currentInputAddr = int(split[1], 16)
        iRecord.currentInputSize = int(split[2], 16)
        sDbg= "Input received at 0x%x for %d bytes" %(iRecord.currentInputAddr,iRecord.currentInputSize)
        log.debug(sDbg)
        
        return iRecord

    def parseImageLine(self, line):
        sDbg= "parsing image line: %s" % (line)
        log.debug(sDbg)

        iRecord = LoadImageTraceRecord()
        
        split = line[2:] #remoe the L identifier, then split with comma
        csplit = split.split(",")
        # Image load, extrac the name from the fullpath               
        iRecord.ImageName = (csplit[0].rsplit("\\",1))[1]
        sDbg= "parsing image: %s" % (iRecord.ImageName)
        log.debug(sDbg)
                    
        iRecord.LoadAddress = int(csplit[1][2:], 16)
        iRecord.ImageSize = int(csplit[3][2:], 16)
       
        return iRecord

    def parseExceptionLine(self,line):
        split = line.split(" ")
        iRecord = ExceptionTraceRecord()
        
        iRecord.currentExceptionAddress = int(split[2], 16)
        iRecord.currentExceptionCode = int(split[1], 16)
        sDbg= "Exception happened at 0x%x with code %x" %(iRecord.currentExceptionAddress,iRecord.currentExceptionCode)
        log.debug(sDbg)
        print("%s" %sDbg)
        
        return iRecord
                            
        
    def parseInstructionLine(self,line):
        
        iRecord = InstructionTraceRecord()
        
        line = line.strip()
        #print("%s\n" %line)
        split = line.split(" ")
        nParts = len(split)
        if split[0] == "E":
            #"Located Instruction header:"
            iRecord.currentInstruction = int(split[1],16)
            iRecord.currentInstSize = self.ins2Encoding[iRecord.currentInstruction].size
            iRecord.sEncoding = self.ins2Encoding[iRecord.currentInstruction].encoding
            iRecord.currentThreadId = int(split[2],16)
            iRecord.currentInstSeq = int(split[3])
            sDbg= "Addr=0x%x, Thread=%x, Seq=%x" %(iRecord.currentInstruction,iRecord.currentThreadId,iRecord.currentInstSeq)
            log.debug(sDbg)
            
            if(nParts<=4):
                return iRecord
            i=4                       
            if(split[i] == "Reg("):
                #read register name and value pair
                i=i+1
                while (split[i] != ")"):
                    #read concrete values from trace
                    reg_value_pair=(split[i]).split("=")
                    regname = reg_value_pair[0]
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
                    
                    j =0;
                    iRecord.currentReadValue = c_byte*iRecord.currentReadSize
                    readBytes = iRecord.currentReadValue()
                    while j<iRecord.currentReadSize:
                        readBytes[j] = int(memBytes[j],16)
                        sDbg= "Offset:%d,Value=0x%x" %(j,readBytes[j])
                        log.debug(sDbg)
                        #TODO: validate if this matches exec simulation
                        j=j+1               
                    i=i+3
                elif (split[i] == "W"):
                    sSize = split[i+1].lstrip()
                    iRecord.currentWriteSize = int(sSize.lstrip(), 10) # in byte                
                    iRecord.currentWriteAddr = int(split[i+2], 16)

                    memBytes = (split[i+3]).split("_")
                    sDbg= "Write %d bytes at 0x%x: " %(iRecord.currentWriteSize,iRecord.currentWriteAddr)
                    log.debug(sDbg)
                    
                    '''
                    j =0;
                    iRecord.currentReadValue = c_byte*iRecord.currentReadSize
                    writeBytes = iRecord.currentWriteValue()
                    while j<iRecord.currentReadSize:
                        writeBytes[j] = int(memBytes[j],16)
                        sDbg= "Offset:%d,Value=0x%x" %(j,writeBytes[j])
                        log.debug(sDbg)
                        #TODO: validate if this matches exec simulation
                        j=j+1
                    '''               
                    return iRecord
                    
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
                            
        