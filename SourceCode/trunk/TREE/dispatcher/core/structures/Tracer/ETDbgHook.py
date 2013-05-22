#!/usr/bin/env python
#---------------------------------------------------------------------
# IDA debug based Execution Trace(ET) callback routines
#
# Version: 1 
# Author: Nathan Li, Xing Li
# Date: 1/10/2013
#---------------------------------------------------------------------

import logging
import sys

from idc import *
from idaapi import *
from idautils import *

from FileOutput.writer import BufferWriter
from FileOutput.writer import FileWriter
from Arch.x86.x86Decoder import x86Decoder
from Arch.x86.x86Decoder import instDecode
from dispatcher.core.structures.Analyzer.x86Decoder import WINDOWS, LINUX

from dispatcher.core.Util import toHex

#curid = 0
nException=0
instSeq = 0

IMMEDIATE=1
REGISTER=2
MEMORY=3

isa_bits=32

class ETDbgHook(DBG_Hooks):

    def __init__(self, targetProcess,logger):
        super(ETDbgHook, self ).__init__()
        self.logger = logger
        self.bDbg = targetProcess.bDbg
        hostOS = None
        if(sys.platform == 'win32'):
            hostOS = WINDOWS
        elif (sys.platform == 'linux2'):
            hostOS = LINUX
        self.xDecoder32 = x86Decoder(isa_bits,32, hostOS)
        #self.memoryWriter = BufferWriter()
        self.memoryWriter = FileWriter()
        self.tracefileName = targetProcess.traceFile
        self.checkInput = None
        self.bCheckFileIO = False
        self.bCheckNetworkIO = False
        self.memoryWriter.fileOpen(self.tracefileName)
        self.startTrace=False
        
    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self.logger.info("Process started, pid=%d tid=%d name=%s ea=0x%x" % (pid, tid, name,ea))
        self.memoryWriter.writeToFile("L %s %x %x\n" % (name, base, size))

    def dbg_process_exit(self, pid, tid, ea, code):
        self.logger.info("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        self.memoryWriter.writeToFile("T 0x%x %d\n" % ( ea, code))
        self.memoryWriter.fileClose()
        
    def dbg_library_unload(self, pid, tid, ea, info):
        self.logger.info("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
        self.memoryWriter.writeToFile("U 0x%x 0x%x\n" % (ea, tid))
        
    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        import idaapi
        self.logger.info("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        idaapi.request_continue_process()
        
    def dbg_process_detach(self, pid, tid, ea):
        self.logger.info("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
            
    def dbg_library_load(self, pid, tid, ea, name, base, size):
        self.logger.info( "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base) )
        self.memoryWriter.writeToFile("L %s %x %x\n" % (name, base,size))
        self.checkInput(name,base,self.bCheckFileIO,self.bCheckNetworkIO)
                                  
    def dbg_trace(self, tid, ip):
        instruction = GetDisasm(ip)
        self.logger.info("Trace: tid=%d 0x%x %s" % (tid, ip, instruction))
        
    def dbg_bpt(self, tid, ea):
        self.logger.info("Breakpoint: tid=%d 0x%x" % (tid, ea))
        
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.

        return 0

    def dbg_suspend_process(self):
        
        if self.startTrace == True:
            self.logger.info( "Process suspended" )
            idc.TakeMemorySnapshot(0)
            idbPath = idc.GetIdbPath()
            idc.SaveBase(idbPath)
            
            self.dbg_step_into()
            idaapi.request_step_into()
            idaapi.run_requests()

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        self.logger.info("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
            pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))  
        self.memoryWriter.writeToFile("X 0x%x 0x%x\n" % (ea, exc_code & idaapi.BADADDR))
        #Check if this is an access violation, exit if it is one because an overflow error has likely occurred.
        exception_code = exc_code & idaapi.BADADDR

        if (exception_code == 0xc0000005):
            self.logger.error("Exception: Access Violation! Stopping Debugger!")
            idc.StopDebugger()
            request_exit_process()

        return 0
    
    def dbg_step_into(self):
        global instSeq
        
        eip = GetRegValue("EIP")
        #threaId = GetCurrentThreadId()
        #self.logger.debug("StepInto: 0x%x, ThreadId: %d" % (eip,threaId))

        """
        #There is a bug somewhere in IDA when we are stepping into code but IDA may not interpert the current instruction as code.
        #This ususally cause inslen to return 0, so we will force the current eip to point to code to avoid this problem.
        #Maybe there is a more elegant way to do this in the future
        if not isCode(GetFlags(eip)):
            DecodeInstruction(eip)
            self.logger.error("0x%x %d     --BAD" % (eip,cmd.size) )
            MakeCode(eip)
            self.logger.error("0x%x %s     --GOOD" % (eip,GetDisasm(eip)) )
        """
        if self.bDbg:
            #self.logger.debug("eip=0x%x size=%d" % (cmd.ea,cmd.size))
            if not isCode(GetFlags(eip)):
                MakeCode(eip)
            self.logger.debug("%s" % GetDisasm(eip))
            
        DecodeInstruction(eip)
        
        inslen = cmd.size
        
        if cmd.size > 0:
            bytes = get_many_bytes(cmd.ea,cmd.size)

            self.memoryWriter.writeToFile("E 0x%x %x %s " % (cmd.ea,cmd.size,toHex(bytes)))
    
            instcode = c_byte*inslen
            instBytes = instcode()
            for i in range(inslen):
                instBytes[i]=get_byte(cmd.ea+i)
    
            curid = idc.GetCurrentThreadId()
            self.memoryWriter.writeToFile("0x%x 0x%x" % (curid, instSeq)) # current_thread_id
            instSeq = instSeq+1
    
            instInfo = instDecode()
            
            if inslen > 0:
                self.xDecoder32.decode_inst(inslen, pointer(instBytes),ctypes.byref((instInfo)))
            else:
                self.logger.error( "Cannot decode instruction at 0x%x %x %s" % (cmd.ea,cmd.size,toHex(bytes)) )
                
            if self.bDbg:
                self.logger.debug("source_operands_number=%d" % (instInfo.n_src_operand))
    
            lReadEA = 0
            lReadSize = 0
            lWriteEA = 0
            lWriteSize = 0
            bSegFS = 0
            
            regs = {}
            for i in range(instInfo.n_src_operand):
                if self.bDbg:
                    self.logger.debug("%d: width=%d, rw=%d, type=%d, ea_string=%s" %(i, instInfo.src_operands[i]._width_bits,instInfo.src_operands[i]._rw,instInfo.src_operands[i]._type,instInfo.src_operands[i]._ea))
                
                if(instInfo.src_operands[i]._type == REGISTER):
                    if(instInfo.src_operands[i]._ea == "STACKPOP"):
                        regs["ESP"] = GetRegValue("ESP")
                    elif((instInfo.src_operands[i]._ea.find("EFLAGS"))!=-1):
                        regs["eflags"] = GetRegValue("EFL")
                    else:
                        regs[instInfo.src_operands[i]._ea]= GetRegValue(instInfo.src_operands[i]._ea)
                elif(instInfo.src_operands[i]._type == MEMORY): #collect registers used to calculate memory address
                    lBase = 0
                    lIndex = 0
                    lScale =0
                    lDisp = 0
                    parts = (instInfo.src_operands[i]._ea).split(":")
                    for part in parts:
                        comps = part.split("=")
                        
                        if self.bDbg:
                            if(len(comps)==2):
                                self.logger.debug("%s is %s"%(comps[0], comps[1]))                    
                        
                        if comps[0] =="SEG":
                            if(comps[1]=="FS"):
                                bSegFS = 1
                                self.logger.debug("SRC SEG==FS")
                            continue
                        elif comps[0] =="BASE":
                            lBase = GetRegValue(comps[1])
                            regs[comps[1]] = GetRegValue(comps[1])
                        elif comps[0] =="INDEX":
                            lIndex = GetRegValue(comps[1])
                            regs[comps[1]] = GetRegValue(comps[1])
                        elif comps[0] =="SCALE":
                            lScale = int(comps[1])
                        elif comps[0] =="DISP":
                            lDisp = int(comps[1])
                        else:
                            break
                    lReadEA = lBase + lIndex*lScale + lDisp
                    if (instInfo.attDisa.find("lea")!=-1): # lea doesn't actually read
                        lReadSize = 0
                        self.logger.debug("Encounter instruction lea:%s" %(instInfo.attDisa))
                    elif (bSegFS==1):
                        lReadSize = 0
                        self.logger.debug("FS segement register ignored for NOW:%s" %(instInfo.attDisa))                    
                    else:
                        lReadSize = instInfo.src_operands[i]._width_bits/8
                    if self.bDbg: 
                        self.logger.debug("lEA = 0x%x" %(lReadEA))                    
            
            if self.bDbg:                 
                self.logger.debug("dest_operands_number=%d" % (instInfo.n_dest_operand))
            for i in range(instInfo.n_dest_operand):
                if self.bDbg: 
                    self.logger.debug("%d: width=%d, rw=%d, type=%d, ea_string=%s" %(i, instInfo.dest_operands[i]._width_bits,instInfo.dest_operands[i]._rw,instInfo.dest_operands[i]._type,instInfo.dest_operands[i]._ea))
                if(instInfo.dest_operands[i]._type == REGISTER):
                    if(instInfo.dest_operands[i]._ea == "STACKPUSH"): #push ino stack
                        regs["ESP"] = GetRegValue("ESP")
                    elif((instInfo.dest_operands[i]._ea.find("EFLAGS"))!=-1):
                        regs["eflags"] = GetRegValue("EFL")
                    else:
                        regs[instInfo.dest_operands[i]._ea]= GetRegValue(instInfo.dest_operands[i]._ea)
                elif(instInfo.dest_operands[i]._type == MEMORY): #collect registers used to calculate memory address
                    lBase = 0
                    lIndex = 0
                    lScale =0
                    lDisp = 0
                    parts = (instInfo.dest_operands[i]._ea).split(":")
                    for part in parts:
                        comps = part.split("=")
                        if self.bDbg: 
                            if(len(comps)==2):
                                self.logger.debug("%s is %s" %(comps[0], comps[1]))             
                        
                        if comps[0] =="SEG":
                            if(comps[1]=="FS"):
                                bSegFS = 1
                                self.logger.debug("DEST: SEG==FS")
                            continue
                        elif comps[0] =="BASE":
                            lBase = GetRegValue(comps[1])
                            regs[comps[1]] = lBase
                            if self.bDbg: 
                                self.logger.debug("BASE %s equals 0x%x" %(comps[1],lBase))
                        elif comps[0] =="INDEX":
                            lIndex = GetRegValue(comps[1])
                            regs[comps[1]] = lIndex
                            if self.bDbg: 
                                self.logger.debug("lIndex %s equals 0x%x" %(comps[1],lIndex))                        
                        elif comps[0] =="SCALE":
                            lScale = int(comps[1])
                            if self.bDbg: 
                                self.logger.debug("lScale equals 0x%x" %(lScale))                                                
                        elif comps[0] =="DISP":
                            lDisp = int(comps[1])
                            if self.bDbg: 
                                self.logger.debug("lDisp equals 0x%x" %(lDisp))                                                                        
                        else:
                            break
                    lWriteEA = lBase + lIndex*lScale + lDisp
                    if (bSegFS==1):
                        lWriteSize = 0
                        self.logger.debug("FS segement register ignored for NOW:%s" %(instInfo.attDisa))                    
                    else:
                        lWriteSize = instInfo.dest_operands[i]._width_bits/8
                    
                    if self.bDbg:   
                        self.logger.debug("lEA = 0x%x" %(lWriteEA))                    
    
            self.memoryWriter.writeToFile(" Reg( ")
            for reg in regs:
                self.memoryWriter.writeToFile("%s=0x%x " %(reg,regs[reg]))
            self.memoryWriter.writeToFile(") ")
    
            if lReadEA!=0 and lReadSize!=0:
                self.memoryWriter.writeToFile("R %d %x " % (lReadSize,lReadEA))
                for j in range(lReadSize):
                    value = DbgByte(lReadEA+j)
                    if(value is not None):
                        if(j==0):
                            self.memoryWriter.writeToFile("%x" %(value))
                        else:
                            self.memoryWriter.writeToFile("_%x" %(value))
                    else:
                        self.memoryWriter.writeToFile("X")    
            if lWriteEA!=0 and lWriteSize!=0: # no need to get contents from the write address
                self.memoryWriter.writeToFile(" W %d %x " % (lWriteSize,lWriteEA))
                
            self.memoryWriter.writeToFile("\n")

            request_step_into()
        else:
            self.logger.error("The instruction at 0x%x has 0 size." % cmd.ea)
        
    def dbg_run_to(self, pid, tid=0, ea=0):
        self.logger.info( "Runto: tid=%d pid=%d address=0x%x" % ( tid, pid, ea) )
        
    def dbg_step_over(self):   
        eip = GetRegValue("EIP") 
        self.logger.info("StepOver: 0x%x %s" % (eip, GetDisasm(eip)))
    
    def dbg_information(self, pid, tid, ea, info):
        self.logger.info("dbg_information: 0x%x %s pid=%d tid=%d info=%s" % (ea, GetDisasm(ea),pid,tid,info))
        
    def dbg_thread_start(self, pid, tid, ea):
        self.logger.info("dbg_thread_start: 0x%x pid=%d tid=%d" % (ea,pid,tid))
        
    def dbg_thread_exit(self, pid, tid, ea, exit_code):
        self.logger.info("dbg_thread_exit: 0x%x pid=%d tid=%d exit_code=%d " % (ea,pid,tid,exit_code))
        
    def dbg_request_error(self, failed_command, failed_dbg_notification):
        self.logger.info("dbg_request_error: failed_command=%d failed_dbg_notification=%d" % (failed_command,failed_dbg_notification) )
        
    def dbg_step_until_ret(self): 
        eip = GetRegValue("EIP") 
        self.logger.info("dbg_step_until_ret: 0x%x %s" % (eip, GetDisasm(eip)))
        
    def callbackProcessing(self,inputLoggingList):
        data_addr = inputLoggingList.pop(0)
        data_size = inputLoggingList.pop(0)
        data = inputLoggingList.pop(0)
        handle = inputLoggingList.pop(0)
        caller_addr = inputLoggingList.pop(0)
        caller_name = inputLoggingList.pop(0)
        thread_id = inputLoggingList.pop(0)
        
        global instSeq

        self.startTrace = True
        self.logger.info( "Taking a memory snapshot then saving to the current idb file.")

        self.logger.info("CallbackProcessing called.  Logging input... I %x %d %s 0x%x 0x%x %s 0x%x 0x%x" % \
             (data_addr,data_size,toHex(data),thread_id,instSeq,caller_name,caller_addr,handle) )
        self.memoryWriter.writeToFile("I %x %d %s 0x%x 0x%x %s 0x%x 0x%x\n" % \
             (data_addr,data_size,toHex(data),thread_id,instSeq,caller_name,caller_addr,handle) )
        
        #update the instruction sequence counter
        instSeq = instSeq+1
        
        """
        eip = GetRegValue("EIP")
        DelBpt(eip)
        """
        PauseProcess()
        

