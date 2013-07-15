import dispatcher.core.Util as Util
from dispatcher.core.DebugPrint import dbgPrint, Print

import idc
import logging
import idaapi
import os.path
import struct

class InteractivemodeFunctions(object):
    def __init__(self):
        self.logger = None
        self.lpBuffer = None
        self.filter = None
        self.tempStack = []
    
    def SetLoggerInstance(self,logger):
        self.logger = logger
        
    def SetDebuggerInstance(self,dbgHook):
        Print("Setting InteractivemodeFunctions debugging instances.")
        self.debuggerInstance = dbgHook

    def SetFilters(self,_filter):
        self.filter = _filter
        
    def startTrace(self):
        self.logger.info("startTrace called")
        self.debuggerInstance.startTrace()
    
    def stopTrace(self):
        self.logger.info("stopTrace called")
        self.debuggerInstance.stopTrace()
        
    def ReadFile(self):
        """
        Monitors the the beginning of ReadFile function
        ReadFile arguments are read from the stack
        This is the function that will trigger the trace
        inputLoggingList holds arguments for 
        """
        
        """  
        BOOL WINAPI ReadFile(
          _In_         HANDLE hFile,
          _Out_        LPVOID lpBuffer,
          _In_         DWORD nNumberOfBytesToRead,
          _Out_opt_    LPDWORD lpNumberOfBytesRead,
          _Inout_opt_  LPOVERLAPPED lpOverlapped
        ); 
        """

        hFile = Util.GetData(0x0)
        self.logger.info( "hFile is 0x%x" % (hFile))
        
        lpBuffer = Util.GetData(0x4)
        self.logger.info( "lpBuffer is 0x%x" % (lpBuffer))
        
        nNumberOfBytesToRead = Util.GetData(0x8)
        self.logger.info( "nNumberOfBytesToRead value is 0x%x" % (nNumberOfBytesToRead))
        
        lpNumberOfBytesRead = Util.GetData(0xC)
        self.logger.info( "lpNumberOfBytesRead value is 0x%x" % (lpNumberOfBytesRead))
        
        lpOverlapped = Util.GetData(0x10)
        self.logger.info( "lpOverlapped is 0x%x" % (lpOverlapped))
        
        ea = idc.GetRegValue("EIP")
        
        retAddr = ea+idc.ItemSize(ea)
        
        Print("The return address is 0x%x" % retAddr)
        
        self.tempStack = []
        self.tempStack.append(lpBuffer)
        self.tempStack.append(lpNumberOfBytesRead)
        self.tempStack.append(hFile)
        self.tempStack.append(ea)

        self.tempStack.append("ReadFile")
        self.tempStack.append(idc.GetCurrentThreadId())

        idc.AddBpt(retAddr)
        idc.SetBptCnd(retAddr,"interactivemodeCallback.ReadFileEnd()")
   
        return 0
    
    def ReadFileEnd(self):
        """
        Monitors the the end of ReadFile function
        This is the function that will trigger the trace
        inputLoggingList is past from MyReadFile, which holds are of MyReadFile arguments
        """
        
        retVal = idc.GetRegValue("EAX")
        self.logger.info( "Returning from ReadFile... with %d" % retVal )
    
        lpBuffer = self.tempStack.pop(0)
        lpNumberOfBytesRead = self.tempStack.pop(0)
        hFile = self.tempStack.pop(0)
        callerAddr = self.tempStack.pop(0)
        callerFuncName = self.tempStack.pop(0)
        threadID = self.tempStack.pop(0)
        
        NumberOfBytesRead = idc.DbgDword(lpNumberOfBytesRead)
        self.logger.info( "NumberOfBytesRead is 0x%x" % NumberOfBytesRead)
        
        _buffer = idaapi.dbg_read_memory(lpBuffer,NumberOfBytesRead)
        
        self.logger.debug( _buffer ) 
        
        inputLoggingList = []
        
        inputLoggingList.append(lpBuffer)
        inputLoggingList.append(NumberOfBytesRead)
        inputLoggingList.append(_buffer)
        inputLoggingList.append(hFile)
        inputLoggingList.append(callerAddr)
        inputLoggingList.append(callerFuncName)
        inputLoggingList.append(threadID)
        
        if retVal:
            Print(  "ReadFile succeeded." )
            self.logger.info( "ReadFile succeeded.")
            self.debuggerInstance.callbackProcessing(inputLoggingList)
        else:
            Print ("ReadFile failed." )
            self.logger.info("ReadFile failed.")
        
        return 0
        