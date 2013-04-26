#---------------------------------------------------------------------
# IDA debug based Execution Trace(ET) callback routines
#
# Version: 1 
# Author: Nathan Li, Xing Li
# Date: 1/10/2013
#---------------------------------------------------------------------

        
def checkWindowsLibs(name,ea,bCheckFileIO,bCheckNetworkIO):
    import idc
    import logging
    
    logger = logging.getLogger('IDATrace')
    idc.RefreshDebuggerMemory()
        
    library_name = name.upper()
    
    if "KERNEL32" in library_name:
        logger.info( "Found kernel32 at 0x%x" % ea )
        
        if bCheckFileIO:
            """
            createFileA_func = idc.LocByName("kernel32_CreateFileA");
            
            if createFileA_func == idc.BADADDR:
                logger.info( "Cannot find CreateFileA" )
            else:
                logger.info( "We found CreateFileA at 0x%x." % createFileA_func )
            idc.AddBpt(createFileA_func)
            idc.SetBptAttr(createFileA_func, idc.BPT_BRK, 0)
            idc.SetBptCnd(createFileA_func, "windowsFileIO.MyCreateFileA()")
            """
            createFileW_func = idc.LocByName("kernel32_CreateFileW");
            
            if createFileW_func == idc.BADADDR:
                logger.info( "Cannot find CreateFileW" )
            else:
                logger.info( "We found CreateFileW at 0x%x." % createFileW_func )
            idc.AddBpt(createFileW_func)
            idc.SetBptAttr(createFileW_func, idc.BPT_BRK, 0)
            idc.SetBptCnd(createFileW_func, "windowsFileIO.MyCreateFileW()")
            
            readFile_func = idc.LocByName("kernel32_ReadFile");
            
            if readFile_func == idc.BADADDR:
                logger.info( "Cannot find ReadFile" )
            else:
                logger.info( "We found ReadFile at 0x%x." % readFile_func )
                
                idc.AddBpt(readFile_func)
                idc.SetBptAttr(readFile_func, idc.BPT_BRK, 0)
                idc.SetBptCnd(readFile_func, "windowsFileIO.MyReadFile()")
            
            closeHandle_func = idc.LocByName("kernel32_CloseHandle");
            
            if closeHandle_func == idc.BADADDR:
                logger.info( "Cannot find CloseHandle" )
            else:
                logger.info( "We found CloseHandle at 0x%x." % closeHandle_func )
                
                idc.AddBpt(closeHandle_func)
                idc.SetBptAttr(closeHandle_func, idc.BPT_BRK, 0)
                idc.SetBptCnd(closeHandle_func, "windowsFileIO.MyCloseHandle()")
    
    elif "WS2_32" in library_name:              
        logger.info( "Found Ws2_32 at 0x%x" % ea )
        
        if bCheckNetworkIO:
            
            recv_func = idc.LocByName("ws2_32_recv");
            
            if recv_func == idc.BADADDR:
                logger.info( "Cannot find ws2_32_recv" )
            else:
                logger.info( "We found ws2_32_recv at 0x%x." % recv_func )
                
                idc.AddBpt(recv_func)
                idc.SetBptAttr(recv_func, idc.BPT_BRK, 0)
                idc.SetBptCnd(recv_func, "windowsNetworkIO.checkRecv()")
                
            bind_func = idc.LocByName("ws2_32_bind");
            
            if bind_func == idc.BADADDR:
                logger.info( "Cannot find ws2_32_bind" )
            else:
                logger.info( "We found ws2_32_bind at 0x%x." % bind_func )
                
                idc.AddBpt(bind_func)
                idc.SetBptAttr(bind_func, idc.BPT_BRK, 0)
                idc.SetBptCnd(bind_func, "windowsNetworkIO.checkBind()")
                
            accept_func = idc.LocByName("ws2_32_accept");
            
            if accept_func == idc.BADADDR:
                logger.info( "Cannot find ws2_32_accept" )
            else:
                logger.info( "We found ws2_32_accept at 0x%x." % accept_func )
                
                idc.AddBpt(accept_func)
                idc.SetBptAttr(accept_func, idc.BPT_BRK, 0)
                idc.SetBptCnd(accept_func, "windowsNetworkIO.checkAccept()")
                
            closesocket_func = idc.LocByName("ws2_32_closesocket");
            
            if closesocket_func == idc.BADADDR:
                logger.info( "Cannot find ws2_32_closesocket" )
            else:
                logger.info( "We found ws2_32_closesocket at 0x%x." % closesocket_func )
                
                idc.AddBpt(closesocket_func)
                idc.SetBptAttr(closesocket_func, idc.BPT_BRK, 0)
                idc.SetBptCnd(closesocket_func, "windowsNetworkIO.checkClosesocket()")
        
    elif "WSOCK32" in library_name:     
        logger.info( "Found wsock32 at 0x%x" % ea )
        
        if bCheckNetworkIO:
            """
            bind_func = idc.LocByName("wsock32_bind");
            
            if bind_func == idc.BADADDR:
                logger.info( "Cannot find wsock32_bind" )
            else:
                logger.info( "We found wsock32_bind at 0x%x." % wsock32_bind )
                
                if idc.isCode(bind_func):
                
                    idc.AddBpt(bind_func)
                    idc.SetBptAttr(bind_func, idc.BPT_BRK, 0)
                    idc.SetBptCnd(bind_func, "windowsNetworkIO.WSOCK32Bind()")
                else:
                    logger.info( "wsock32_bind at 0x%x is data not code." % bind_func )
                """
            recv_func = idc.LocByName("wsock32_recv")
            
            if recv_func == idc.BADADDR:
                logger.info( "Cannot find wsock32_recv" )
            else:
                logger.info( "We found wsock32_recv at 0x%x." % recv_func )
                
                if idc.isCode(recv_func):
                    
                    idc.AddBpt(recv_func)
                    idc.SetBptAttr(recv_func, idc.BPT_BRK, 0)
                    idc.SetBptCnd(recv_func, "windowsNetworkIO.WSOCK32Recv()")
                else:
                    logger.info( "wsock32_recv at 0x%x is data not code." % recv_func )
             
def checkLinuxLibs(name,ea):
    
    library_name = name.upper()
    print "Checking Linux for library " + library_name
    
    if "LIBC" in library_name:
        import idc
        import logging
        
        print "Found Libc at 0x%x" % ea
        logger = logging.getLogger('IDATrace')
        
        logger.info( "Found Libc at 0x%x" % ea )
        idc.RefreshDebuggerMemory()              
        
        fopen_func = idc.LocByName("_IO_file_fopen");
        
        if fopen_func == idc.BADADDR:
            logger.info( "Cannot find _IO_file_fopen" )
            print "Cannot find _IO_file_fopen."
        else:
            logger.info( "We found _IO_file_fopen at 0x%x." % fopen_func )
            print "We found _IO_file_fopen at 0x%x." % fopen_func 
            idc.AddBpt(fopen_func)
            idc.SetBptAttr(fopen_func, idc.BPT_BRK, 0)
            idc.SetBptCnd(fopen_func, "linuxFileIO.My_fopen()")
        
        fread_func = idc.LocByName("_IO_fread");
        
        if fread_func == idc.BADADDR:
            logger.info( "Cannot find _IO_fread" )
            print "Cannot find _IO_fread."
        else:
            logger.info( "We found _IO_fread at 0x%x." % fread_func )
            print "We found _IO_fread at 0x%x." % fread_func  
            idc.AddBpt(fread_func)
            idc.SetBptAttr(fread_func, idc.BPT_BRK, 0)
            idc.SetBptCnd(fread_func, "linuxFileIO.My_fread()")

        fclose_func = idc.LocByName("_IO_fclose");
        
        if fclose_func == idc.BADADDR:
            logger.info( "Cannot find _IO_fclose" )
            print "Cannot find _IO_fclose."
        else:
            logger.info( "We found _IO_fclose at 0x%x." % fclose_func )
            print "We found _IO_fclose at 0x%x." % fclose_func  
            idc.AddBpt(fclose_func)
            idc.SetBptAttr(fclose_func, idc.BPT_BRK, 0)
            idc.SetBptCnd(fclose_func, "linuxFileIO.My_fclose()")
        
def checkMacOSXLibs(name,ea):
    print "Checking Mac OSX"
    