# TREE - Taint-enabled Reverse Engineering Environment 
# Copyright (c) 2013 Battelle BIT Team - Nathan Li, Xing Li, Loc Nguyen
#
# All rights reserved.
#
# For detailed copyright information see the file license.txt in the IDA PRO plugins folder
#---------------------------------------------------------------------
# ETDbgHookMobile.py - IDA Pro debugger hook class for mobile, callbacks for all debugger functionalities
#---------------------------------------------------------------------

import logging
import sys

from idc import *
from idaapi import *
from idautils import *

from dispatcher.core.Util import toHex
from dispatcher.core.structures.Tracer.FileOutput.writer import BufferWriter

#curid = 0
nException=0
instSeq = 0

IMMEDIATE=1
REGISTER=2
MEMORY=3

class ETDbgHookMobile(DBG_Hooks):
    """
    Execution Trace Debugger hook
    This class receives notifications from the actually IDA Pro debugger
    """
    def __init__(self,traceFile,treeTraceFile,logger,mode):
        super(ETDbgHookMobile, self ).__init__()
        self.logger = logger

        self.memoryWriter = BufferWriter()
        
        self.memoryWriter.fileOpen(traceFile)

        self.treeIDBFile = treeTraceFile
        self.startTracing = False
        self.interactiveMode = mode

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        """
        Notified when a process starts
        This is a standard IDA Debug Hook callback
        """
        self.logger.info("Process started, pid=%d tid=%d name=%s ea=0x%x" % (pid, tid, name,ea))
        self.memoryWriter.writeToFile("L %s %x %x\n" % (name, base, size))

    def dbg_process_exit(self, pid, tid, ea, code):
        """
        Notified when a process exits
        This is a standard IDA Debug Hook callback
        """
        self.logger.info("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        self.memoryWriter.writeToFile("T 0x%x %d\n" % ( ea, code))
        data = self.memoryWriter.getBufferData()
        self.takeSnapshot(data)
        self.memoryWriter.fileClose(data)
                
    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        """
        Notified when the debugger attaches to a process
        This is a standard IDA Debug Hook callback
        """    
        self.logger.info("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        
    def dbg_process_detach(self, pid, tid, ea):
        """
        Notified when the debugger detaches from a process
        This is a standard IDA Debug Hook callback
        """
        self.logger.info("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
        
        self.memoryWriter.writeToFile("T 0x%x\n" % ( ea))
        data = self.memoryWriter.getBufferData()
        self.takeSnapshot(data)
        self.memoryWriter.fileClose(data)
        
    def dbg_library_unload(self, pid, tid, ea, info):
        """
        Notified when a library unloads
        This is a standard IDA Debug Hook callback
        """
        self.logger.info("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
        self.memoryWriter.writeToFile("U 0x%x 0x%x\n" % (ea, tid))
        
    def dbg_library_load(self, pid, tid, ea, name, base, size):
        """
        Notified when a library loads
        We use this callback to monitor which library loads into memory so we can hook the appropriate functions for monitoring
        This is a standard IDA Debug Hook callback
        """
        self.logger.info( "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base) )
        self.memoryWriter.writeToFile("L %s %x %x\n" % (name, base,size))
                                  
    def dbg_trace(self, tid, ip):
        """
        Notified when the debugger is in IDA Pro's trace mode
        This is a standard IDA Debug Hook callback
        """
        instruction = GetDisasm(ip)
        self.logger.info("Trace: tid=%d 0x%x %s" % (tid, ip, instruction))
        
    def dbg_bpt(self, tid, ea):
        """
        Notified when the debugger hits a breakpoint
        This is a standard IDA Debug Hook callback
        """
        self.logger.info("Breakpoint: tid=%d 0x%x" % (tid, ea))
        
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.

        return 0

    def dbg_suspend_process(self):
        """
        Notified when the current debugged process is being suspended
        We force the debugger into suspend mode as a way to notify the tracer to start tracing
        TakeMemorySnapshot is called to capture all the memory content of the debugger at this point.
        This will have all the loaded DLLs / libraries in memory
        If the debugger is suspend for any other reason, we will not trace
        This is a standard IDA Debug Hook callback
        """
        
        if self.startTracing:
            self.startTracing = False
            self.logger.info( "Process suspended" )
            
            idc.TakeMemorySnapshot(0)
            
            self.dbg_step_into()
            idaapi.request_step_into()
            idaapi.run_requests()
        else:
            self.logger.info("suspend process called but not to start tracing")

                   
    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        """
        Notified when the debugger hits an exception
        This is a standard IDA Debug Hook callback
        """
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
        """
        Notified when the debugger is single stepping thru a process
        This is the main function for tracing, we analyze each instruction being executed
        The instruction along with its metadata is written to either memory or out to a file
        This is a standard IDA Debug Hook callback
        """

        global instSeq
        
        eip = here()

        #DecodeInstruction(eip)
        
        
        """
        data_line = ""
        
        #Haven't found a good way to get all the registers
        #This routine causes GetRegValue to error out because some of the registers do not have value
        
        for register in GetRegisterList():
            reg_val = GetRegValue(register)
            data_str = "%s = 0x%x  "
            data_line = data_line + data_str
        """
        """
        inslen = cmd.size
        
        if cmd.size > 0:
            bytes = get_many_bytes(cmd.ea,cmd.size)

            #Manually printing general register values (from the debugger)
            registers = "R0=0x%x, R1=0x%x, R2=0x%x, R3=0x%x, R4=0x%x, R5=0x%x, R6=0x%x, R7=0x%x, R8=0x%x, " \
                        "R9=0x%x, R10=0x%x, R11=0x%x, R12=0x%x, SP=0x%x, LR=0x%x, PC=0x%x, PSR=0x%x" \
                        % (GetRegValue('R0'),GetRegValue('R1'),GetRegValue('R2'),GetRegValue('R3'), \
                           GetRegValue('R4'),GetRegValue('R5'),GetRegValue('R6'),GetRegValue('R7'), \
                           GetRegValue('R8'),GetRegValue('R9'),GetRegValue('R10'),GetRegValue('R11'), \
                           GetRegValue('R12'),GetRegValue('SP'),GetRegValue('LR'),GetRegValue('PC'),GetRegValue('PSR'))
                          
            print registers
            
            self.memoryWriter.writeToFile("E 0x%x %x %s %s" % (cmd.ea,cmd.size,toHex(bytes),registers))
                
            self.memoryWriter.writeToFile("\n")

            request_step_into()
        else:
            self.logger.error("The instruction at 0x%x has 0 size." % cmd.ea)
        """
        print("Stepping 0x%x" % eip)
        request_step_into()
        
    def dbg_run_to(self, pid, tid=0, ea=0):
        """
        Notified when the debugger was set to run to a certain point
        This is a standard IDA Debug Hook callback
        """
        self.logger.info( "Runto: tid=%d pid=%d address=0x%x" % ( tid, pid, ea) )
        
    def dbg_step_over(self):
        """
        Notified when the debugger steps over command is called
        This is a standard IDA Debug Hook callback
        """
        eip = here()
        self.logger.info("StepOver: 0x%x %s" % (eip, GetDisasm(eip)))
    
    def dbg_information(self, pid, tid, ea, info):
        self.logger.info("dbg_information: 0x%x %s pid=%d tid=%d info=%s" % (ea, GetDisasm(ea),pid,tid,info))
        
    def dbg_thread_start(self, pid, tid, ea):
        """
        Notified when a thread has started
        This is a standard IDA Debug Hook callback
        """
        self.logger.info("dbg_thread_start: 0x%x pid=%d tid=%d" % (ea,pid,tid))
        
    def dbg_thread_exit(self, pid, tid, ea, exit_code):
        """
        Notified when a thread has exited
        This is a standard IDA Debug Hook callback
        """
        self.logger.info("dbg_thread_exit: 0x%x pid=%d tid=%d exit_code=%d " % (ea,pid,tid,exit_code))
        
    def dbg_request_error(self, failed_command, failed_dbg_notification):
        """
        Notified when the debugger encounters an error
        This is a standard IDA Debug Hook callback
        """
        self.logger.info("dbg_request_error: failed_command=%d failed_dbg_notification=%d" % (failed_command,failed_dbg_notification) )
        
    def dbg_step_until_ret(self):
        """
        Notified when the step until ret command is called
        This is a standard IDA Debug Hook callback
        """
        eip = here()
        self.logger.info("dbg_step_until_ret: 0x%x %s" % (eip, GetDisasm(eip)))

    def startTrace(self):
        self.startTracing = True
        PauseProcess()

    def stopTrace(self):
        self.startTracing = False
        idaapi.request_detach_process()
        idaapi.run_requests()
          
    def takeSnapshot(self,data):
        """
        This function saves the current state of the debugger, whatever is in the IDB database, all of its memory content
        into a netnode which then gets saved to a new IDB file
        The data is the entire execution trace in memory.  A blob is used to stored the trace.
        @param data: The data to save into the netnode, this is the entire execution trace in memory
        @return: None        
        """
        ExTraces = idaapi.netnode("$ ExTraces", 0, True)

        ExTraces.setblob(data,0,'A')
            
        idc.SaveBase(self.treeIDBFile)