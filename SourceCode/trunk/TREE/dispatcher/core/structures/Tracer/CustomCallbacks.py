import dispatcher.core.Util as Util

import idc
import logging
import os.path
import idaapi

from dispatcher.core.DebugPrint import dbgPrint, Print

class CustomApiFunctions(object):
    def __init__(self):
        import logging
        
        self.logger = logging.getLogger('IDATrace')
        self.debuggerInstance = None
        self.filter = None
        
    def SetDebuggerInstance(self,dbgHook):
        self.debuggerInstance = dbgHook
    
    def SetFilters(self,_filter):
        self.filter = _filter
        
    def MyBmfdOpenFontContext(self):
        bufferLength = Util.GetData(0x4)
        
    def MySioctlDeviceControlCrashMonitor(self):
        import idc
        
        idc.RefreshDebuggerMemory() 
        
        pBuffer = Util.GetData(0x0)        
        bufferLength = Util.GetData(0x4)

        DataFromUser = idaapi.dbg_read_memory(pBuffer,bufferLength)
        self.logger.info("KERNELOV.SYS: Data from User = %s" % DataFromUser )

        self.debuggerInstance.callbackProcessing(pBuffer,bufferLength,DataFromUser)
        self.debuggerInstance.dbg_step_into()
        idaapi.request_step_into()
        idaapi.run_requests()
        
        return 0

    def MyNtUserMessageCall(self):
        """
        BOOL NTAPI NtUserMessageCall	(
        HWND 	hWnd,
        UINT 	Msg,
        WPARAM 	wParam,
        LPARAM 	lParam,
        ULONG_PTR 	ResultInfo,
        DWORD 	dwType,
        BOOL 	Ansi 
        )		
        """
        
        #idc.RefreshDebuggerMemory()
        
        hWnd = Util.GetData(0x4)        
        uMsg = Util.GetData(0x8)

        Print( "MyNtUserMessageCall from Win32k.sys: hWnd=0x%x uMsg=%d" % (hWnd,uMsg) )
        
        self.logger.info("MyNtUserMessageCall from Win32k.sys: hWnd=0x%x uMsg=%d" % (hWnd,uMsg) )
        
        return 0
    
    def MySioctlDeviceControl(self):
        """
        NTSTATUS
        SioctlDeviceControl(
        IN PDEVICE_OBJECT pDeviceObject,
        IN PIRP pIrp
        )
        """
        
        """
        Irp->UserBuffer //offset 0x3c
        AssociatedIrp.SystemBuffer //offset 0xC
        
        struct {
            ULONG  OutputBufferLength; //offset 0x64
            ULONG POINTER_ALIGNMENT  InputBufferLength; //offset 0x68
            ULONG POINTER_ALIGNMENT  IoControlCode; //offset 0x6c
            PVOID  Type3InputBuffer; //offset 0x70
        } DeviceIoControl; //offset 0x60
        """
    
        pDeviceObject = Util.GetData(0x4)        
        pIrp = Util.GetData(0x8)

        #idaapi.dbg_read_memory(self.lpBuffer,NumberOfBytesRead)
        SystemBuffer = idc.DbgDword(pIrp+0xC)
        self.logger.info("KERNELOV.SYS: Irp->AssociatedIrp.SystemBuffer = 0x%x" % SystemBuffer)
        
        UserBuffer = idc.DbgDword(pIrp+0x3C)
        self.logger.info("KERNELOV.SYS: Irp->UserBuffer = 0x%x" % UserBuffer )
        
        Type3InputBuffer = idc.DbgDword(pIrp + 0x6C)
        self.logger.info("KERNELOV.SYS: irpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%x" % Type3InputBuffer)
        
        InputBufferLength = idc.DbgDword(pIrp + 0x68)
        self.logger.info("KERNELOV.SYS: irpSp->Parameters.DeviceIoControl.InputBufferLength = %d" % InputBufferLength)
        
        OutputBufferLength = idc.DbgDword(pIrp + 0x64) 
        self.logger.info("KERNELOV.SYS: irpSp->Parameters.DeviceIoControl.OutputBufferLength = %d" % OutputBufferLength )

        return 0
    