#---------------------------------------------------------------------
# IDA debug based Execution Trace(ET) callback routines
#
# Version: 1 
# Author: Nathan Li, Xing Li
# Date: 1/10/2013
#---------------------------------------------------------------------

import dispatcher.core.Util as Util

import idc
import logging
import idaapi
import os.path
import struct
        
class IO(object):
    def __init__(self):
        self.logger = None
        self.lpBuffer = None
        self.filter = None
        
    def SetLoggerInstance(self,logger):
        self.logger = logger
        
    def SetDebuggerInstance(self,dbgHook):
        self.debuggerInstance = dbgHook

    def SetFilters(self,_filter):
        self.filter = _filter
    
class FileIO(IO):
    
    def __init__(self):
        super(FileIO, self).__init__() 
        self.lpBuffer = None
        self.lpNumberOfBytesRead = None
        self.handleSet = set()

    def MyCreateFileAEnd(self):
        handle = idc.GetRegValue("EAX")
        self.logger.info( "MyCreateFileAEnd HANDLE is 0x%x" % handle)
        return 0

    def MyCreateFileA(self):
        """
        HANDLE WINAPI CreateFile(
        _In_      LPCTSTR lpFileName,
        _In_      DWORD dwDesiredAccess,
        _In_      DWORD dwShareMode,
        _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_      DWORD dwCreationDisposition,
        _In_      DWORD dwFlagsAndAttributes,
        _In_opt_  HANDLE hTemplateFile
        );
        """
    
        lpFileName = Util.GetData(0x4)
        self.logger.info( "MyCreateFileA lpFileName is 0x%x" % lpFileName)
    
        filePath = "".join(Util.Read(lpFileName,1))
        
        self.logger.info( "filePath is %s" % filePath)
        
        dwDesiredAccess = Util.GetData(0x8)
        self.logger.info( "dwDesiredAccess is 0x%x" % (dwDesiredAccess))
    
        dwShareMode = Util.GetData(0xC)
        self.logger.info( "dwShareMode value is 0x%x" % (dwShareMode))
        
        lpSecurityAttributes = Util.GetData(0x10)
        self.logger.info( "lpSecurityAttributes value is 0x%x" % (lpSecurityAttributes))
    
        dwCreationDisposition = Util.GetData(0x14)
        self.logger.info( "dwCreationDisposition value is 0x%x" % (dwCreationDisposition))
    
        dwFlagsAndAttributes = Util.GetData(0x18)
        hTemplateFile = Util.GetData(0x1C)
    
        fileName = os.path.basename(filePath)
        
        self.logger.info( "The filename is %s" % fileName)
        
        retAddr = Util.GetData(0x0)
        idc.AddBpt(retAddr)
        idc.SetBptCnd(retAddr,"windowsFileIO.MyCreateFileAEnd()")
        
        return 0
    
    def MyCreateFileWEnd(self):
        #print "Returning from CreateFileW..."
        handle = idc.GetRegValue("EAX")

        self.handleSet.add(handle)
        self.logger.info( "HANDLE is 0x%x" % handle)
            
        return 0
    
    def MyCreateFileW(self):
        """
        HANDLE WINAPI CreateFileW(
        _In_      LPCTSTR lpFileName,
        _In_      DWORD dwDesiredAccess,
        _In_      DWORD dwShareMode,
        _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_      DWORD dwCreationDisposition,
        _In_      DWORD dwFlagsAndAttributes,
        _In_opt_  HANDLE hTemplateFile
        );
        """
        
        lpFileName = Util.GetData(0x4)
        self.logger.info( "MyCreateFileW lpFileName is 0x%x" % lpFileName)
         
        filePath = "".join(Util.Read(lpFileName,2))
        
        self.logger.info( "filePath is %s" % filePath)
        
        dwDesiredAccess = Util.GetData(0x8)
        self.logger.info( "dwDesiredAccess is 0x%x" % (dwDesiredAccess))
    
        dwShareMode = Util.GetData(0xC)
        self.logger.info( "dwShareMode value is 0x%x" % (dwShareMode))
        
        lpSecurityAttributes = Util.GetData(0x10)
        self.logger.info( "lpSecurityAttributes value is 0x%x" % (lpSecurityAttributes))
    
        dwCreationDisposition = Util.GetData(0x14)
        self.logger.info( "dwCreationDisposition value is 0x%x" % (dwCreationDisposition))
    
        dwFlagsAndAttributes = Util.GetData(0x18)
        hTemplateFile = Util.GetData(0x1C)
    
        fileName = os.path.basename(filePath)
        
        self.logger.info( "The filename is %s" % fileName)

        retAddr = Util.GetData(0x0)
        
        if fileName in self.filter['file']:
            idc.AddBpt(retAddr)
            idc.SetBptAttr(retAddr, idc.BPT_BRK, 0)
            idc.SetBptCnd(retAddr,"windowsFileIO.MyCreateFileWEnd()")
            self.logger.info( "Filter matched. Add handle to the handle's dictionary to start logging.")
            #print "Filter matched. Add handle to the handle's dictionary to start logging."

        else:
            if idc.CheckBpt(retAddr) >= 0:
                #print "Removing un-needed breakpoint."
                self.logger.info("Removing un-needed breakpoint.")
                idc.DelBpt(retAddr)
                
            self.logger.info( "Filter did not match.")
        
        return 0
    
    def MyCloseHandle(self):
        """
        BOOL WINAPI CloseHandle(
            _In_  HANDLE hObject
          );
          
        """
        
        hObject = Util.GetData(0x4)
        #threaId = idc.GetCurrentThreadId()
        
        #  "MyCloseHandle hFile is 0x%x" % (hObject)
        #self.logger.info( "MyCloseHandle [%d] hFile is 0x%x" % (threaId,hObject) )

        if hObject in self.handleSet:
            self.handleSet.remove(hObject)
            self.logger.info("Removing handle 0x%x from Handle Set" % hObject)
            # "Removing handle 0x%x from Handle Set" % hObject

        return 0
    
    def MyReadFileEnd(self):

        retVal = idc.GetRegValue("EAX")
        self.logger.info( "Returning from ReadFile... with %d" % retVal )
    
        NumberOfBytesRead = idc.DbgDword(self.lpNumberOfBytesRead)
        self.logger.info( "NumberOfBytesRead is 0x%x" % NumberOfBytesRead)
        
        _buffer = idaapi.dbg_read_memory(self.lpBuffer,NumberOfBytesRead)
        
        self.logger.debug( _buffer ) 
        
        if retVal:
           # print  "ReadFile succeeded."
            self.logger.info( "ReadFile succeeded.")
            self.debuggerInstance.callbackProcessing(self.lpBuffer,NumberOfBytesRead,_buffer)
            
        else:
           # print "ReadFile failed."
            self.logger.info("ReadFile failed.")
        
        return 0
        
    def MyReadFile(self):
        """  
        BOOL WINAPI ReadFile(
          _In_         HANDLE hFile,
          _Out_        LPVOID lpBuffer,
          _In_         DWORD nNumberOfBytesToRead,
          _Out_opt_    LPDWORD lpNumberOfBytesRead,
          _Inout_opt_  LPOVERLAPPED lpOverlapped
        ); 
        """

        hFile = Util.GetData(0x4)
        self.logger.info( "hFile is 0x%x" % (hFile))
        
        self.lpBuffer = Util.GetData(0x8)
        self.logger.info( "lpBuffer is 0x%x" % (self.lpBuffer))
        
        nNumberOfBytesToRead = Util.GetData(0xC)
        self.logger.info( "nNumberOfBytesToRead value is 0x%x" % (nNumberOfBytesToRead))
        
        self.lpNumberOfBytesRead = Util.GetData(0x10)
        self.logger.info( "lpNumberOfBytesRead value is 0x%x" % (self.lpNumberOfBytesRead))
        
        lpOverlapped = Util.GetData(0x14)
        self.logger.info( "lpOverlapped is 0x%x" % (lpOverlapped))
        
        retAddr = Util.GetData(0x0)
        
        if hFile in self.handleSet:
            self.logger.info("Ready to read from handle 0x%x" % hFile )
            #print "Ready to read from handle 0x%x" % hFile
            idc.AddBpt(retAddr)
            idc.SetBptCnd(retAddr,"windowsFileIO.MyReadFileEnd()")
        else:
            if idc.CheckBpt(retAddr) >= 0:
                self.logger.info("Removing un-needed ReadFile breakpoint.")
              #  print "Removing un-needed ReadFile breakpoint."
                idc.DelBpt(retAddr)
            
        return 0

class NetworkIO(IO):
    def __init__(self):
        super(NetworkIO, self).__init__() 
        self.socket_dict = dict()
        self.tempStack = []

    def checkRecvEnd(self):
        
        s = self.tempStack.pop(0)
        buf = self.tempStack.pop(0)
        _len = self.tempStack.pop(0)
        
        _buffer = idaapi.dbg_read_memory(buf,_len)

        self.logger.debug( "buffer is %s" % _buffer )
        
        bytesRecv = idc.GetRegValue("EAX")
        self.logger.info( "Number bytes received %d" % bytesRecv )
        
        if bytesRecv > 0:
            self.logger.info( "recv succeeded." )
            
            if self.socket_dict.has_key(s):
                self.logger.info( "Found socket 0x%x" % s )
                self.debuggerInstance.callbackProcessing(buf,_len,_buffer)

            else:
                self.logger.info( "Cannot find socket socket 0x%x" % s )


        else:
            self.logger.error( "Recv function failed." )
    
        return 0

            
    def checkRecv(self):
        """
        int recv(
        _In_   SOCKET s,
        _Out_  char *buf,
        _In_   int len,
        _In_   int flags
         );
        """
        
        s = Util.GetData(0x4)
        self.logger.info( "Socket is 0x%x" % (s) )
        
        buf = Util.GetData(0x8)
        self.logger.info( "*buf is 0x%x" % (buf) )
        
        _len = Util.GetData(0xC)
        self.logger.info( "len value is %d" % (_len) )
        
        flag = Util.GetData(0x10)
        self.logger.info( "flag value is %d" % (flag) )
  
        retAddr = Util.GetData(0x0)

        self.tempStack.append(s)
        self.tempStack.append(buf)
        self.tempStack.append(_len)

        idc.AddBpt(retAddr)
        idc.SetBptAttr(retAddr, idc.BPT_BRK, 0)
        idc.SetBptCnd(retAddr,"windowsNetworkIO.checkRecvEnd()")
        
        return 0
        

    def checkBindEnd(self):        
        retVal = idc.GetRegValue("EAX")
        
        if retVal==0:
            self.logger.info( "Bind succeeded.")
            socket = self.tempStack.pop(0)
            port = self.tempStack.pop(0)
            print "the port is " + port
            self.socket_dict[socket]=port
        else:
            self.logger.info ("Bind failed.")         

        return 0
    
    def checkBind(self):
  
        """  
        int bind(
          _In_  SOCKET s,
          _In_  const struct sockaddr *name,
          _In_  int namelen
        );
        
        struct sockaddr_in {
            short   sin_family;
            u_short sin_port;
            struct  in_addr sin_addr;
            char    sin_zero[8];
        };
        """

        s = Util.GetData(0x4)
        self.logger.info ("SOCKET is 0x%x" % (s))
        
        sockaddr_name = Util.GetData(0x8)
        self.logger.info ("sockaddr_name is 0x%x" % (sockaddr_name))
        
        port = struct.unpack(">H", idaapi.dbg_read_memory(sockaddr_name+0x2,2) )
        portName = str(port[0])
        self.logger.info ("port value is %s" % (portName))
        
        namelen = Util.GetData(0xC)
        self.logger.info ("namelen value is %d" % (namelen))

        retAddr = Util.GetData(0x0)
        print self.filter['network']
        if portName in self.filter['network']:
            self.tempStack.append(s)
            self.tempStack.append(portName)
            idc.AddBpt(retAddr)
            idc.SetBptAttr(retAddr, idc.BPT_BRK, 0)
            idc.SetBptCnd(retAddr,"windowsNetworkIO.checkBindEnd()")
            self.logger.info( "Netork Filter matched. Adding port to the Handle's dictionary to start logging.")
            #print "Filter matched. Add handle to the handle's dictionary to start logging."

        else:
            if idc.CheckBpt(retAddr) >= 0:
                #print "Removing un-needed breakpoint."
                self.logger.info("Removing un-needed breakpoint.")
                idc.DelBpt(retAddr)
                
            self.logger.info( "Network Filter did not match.")
            
        return 0
            
    def checkAcceptEnd(self):

        recvSocket = idc.GetRegValue("EAX")
        self.logger.info("The receive socket is 0x%x" % recvSocket)
        
        socket = self.tempStack.pop(0)
        if self.socket_dict.has_key(socket):
            self.logger.info("checkAccept: Found key 0x%x in dictionary." % (socket))
            _port = self.socket_dict.get(socket)
            self.socket_dict[recvSocket] = self.socket_dict[socket]
            del self.socket_dict[socket]

    def checkAccept(self):
        """
        SOCKET accept(
          _In_     SOCKET s,
          _Out_    struct sockaddr *addr,
          _Inout_  int *addrlen
        );
        """

        s = Util.GetData(0x4)
        self.logger.info("SOCKET is 0x%x" % (s))
         
        sockaddr_addr = Util.GetData(0x8)
        self.logger.info("sockaddr_addr is 0x%x" % (sockaddr_addr))
  
        addrlen =Util.GetData(0xC)
        self.logger.info("*addrlen value is 0x%x" % (addrlen))
        
        retAddr = Util.GetData(0x0)

        self.tempStack.append(s)

        idc.AddBpt(retAddr)
        idc.SetBptAttr(retAddr, idc.BPT_BRK, 0)
        idc.SetBptCnd(retAddr,"windowsNetworkIO.checkAcceptEnd()")            

        return 0
    
    def checkClosesocketEnd(self):
            
        retVal = idc.GetRegValue("EAX")
        
        if retVal==0:
            s = self.tempStack.pop(0)
            if self.socket_dict.has_key(s):
                del self.socket_dict[s]
                self.logger.info("Removing socket 0x%x from socket dictionary.")
        else:
            
            self.logger.info("Socket closed.")
            
        return 0
  
    def checkClosesocket(self):
        """
        int closesocket(
          _In_  SOCKET s
        );
        """

        s = Util.GetData(0x4)
        self.logger.info("SOCKET is 0x%x" % (s))
        
        retAddr = Util.GetData(0x0)
        self.tempStack.append(s)

        idc.AddBpt(retAddr)
        idc.SetBptAttr(retAddr, idc.BPT_BRK, 0)
        idc.SetBptCnd(retAddr,"windowsNetworkIO.checkClosesocketEnd()")
        
        return 0

