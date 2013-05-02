#---------------------------------------------------------------------
# IDA debug based Execution Trace(ET) callback routines
#
# Version: 1 
# Author: Nathan Li, Xing Li
# Date: 1/10/2013
#---------------------------------------------------------------------

import dispatcher.core.Util as Util
from dispatcher.core.DebugPrint import dbgPrint, Print

import idc
import logging
import os.path
import idaapi

class FileIO:
    
    def __init__(self):
        self.logger = None
        self.debuggerInstance = None
        self.filter = None
        self.pBuffer = None
        self.pSize = 0
        self.handleSet = set()
    
    def SetLoggerInstance(self,logger):
        self.logger = logger
        
    def SetDebuggerInstance(self,dbgHook):
        self.debuggerInstance = dbgHook
    
    def SetFilters(self,_filter):
        self.filter = _filter
        
    def My_freadEnd(self):
        _buffer = idaapi.dbg_read_memory(self.pBuffer,self.pSize)
        self.logger.debug( _buffer)
        
        numBytesRead = idc.GetRegValue("EAX")
        self.logger.info( "_fread read %d bytes." % (numBytesRead) )
        
        if numBytesRead > 0:
            self.logger.info( "_fread succeeded.")
            self.debuggerInstance.callbackProcessing(self.pBuffer,self.pSize,_buffer)
        else:
            self.logger.info( "_fread failed.")
        
        return 0
        
    def My_fread(self):
  
        """  
        old - size_t fread ( void * ptr, size_t size, size_t count, FILE * stream );
        
        size_t _IO_fread (void * ptr, size_t size, size_t count, FILE * stream )
        
        """
        
        ptr = Util.GetData(0x4)
        self.logger.info( "fp is 0x%x" % (ptr))

        _size = Util.GetData(0x8)
        self.logger.info( "size is %d" % (_size))
        
        _count = Util.GetData(0xc)
        self.logger.info( "count is %d" % (_count))
        
        stream = Util.GetData(0x10)
        self.logger.info( "stream is 0x%x" % (stream))
        
        self.pSize = _size * _count
        self.pBuffer = ptr

        retAddr = Util.GetData(0x0)
        """
        Not sure if I need this, comment out for now
        
        bptConstant = idc.CheckBpt(retAddr)
            
        if bptConstant != idc.BPTCK_NONE:
            idc.DelBpt(retAddr)
        """    
        if stream in self.handleSet:
            self.logger.info( "Found stream 0x%x" % stream)
            
            idc.AddBpt(retAddr)
            idc.SetBptAttr(retAddr, idc.BPT_BRK, 0)
            idc.SetBptCnd(retAddr,"linuxFileIO.My_freadEnd()")
        else:
            self.logger.info( "Cannot find handle 0x%x" % stream)

        return 0
    
    def My_fopenEnd(self):
        """
        Not need to call this function here since fopen already contains the handle
        """
        stream = idc.GetRegValue("EAX")
        
        self.logger.info( "HANDLE is 0x%x" % stream)
        self.handleSet.add(stream)
    
        return 0
    
    def My_fopen(self):
        """
        old - FILE * fopen ( const char * filename, const char * mode );
        
        FILE * _IO_file_fopen (fp, filename, mode, is32not64)
        
        """

        fp = Util.GetData(0x4)
        self.logger.info( "fp is 0x%x" % fp)
        
        filename = Util.GetData(0x8)
         
        filePath = "".join(Util.Read(filename,1))
        
        self.logger.info( "filePath is %s" % filePath)
        
        mode = Util.GetData(0xC)
        self.logger.info( "mode is 0x%x" % (mode))
        
        is32not64 = Util.GetData(0x10)
        self.logger.info("is32not64 is %d" % (is32not64))
        
        fileName = os.path.basename(filePath)
        
        self.logger.info( "The filename is %s" % fileName)
        
        if fileName in self.filter['file']:
            self.handleSet.add(fp)
            self.logger.info( "Filter matched. Add handle to the handle's dictionary to start logging.")
        else:
            self.logger.info( "Filter did not match.")
            
        return 0
    
    def My_fclose(self):
        """
        int fclose ( FILE * stream );          
        """
        stream = Util.GetData(0x4)
        self.logger.info( "stream is 0x%x" % (stream) )
        
        retVal = idc.GetRegValue("EAX")
        
        return 0
