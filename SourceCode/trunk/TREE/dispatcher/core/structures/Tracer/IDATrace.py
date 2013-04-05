#---------------------------------------------------------------------
# IDA debug based Execution Trace(ET) callback routines
#
# Version: 1 
# Author: Nathan Li, Xing Li
# Date: 1/10/2013
#---------------------------------------------------------------------

class IDATrace():
    
    def __init__(self,funcCallbacks):
        """
        This is the start of the debugger.
        """
        self.windowsFileIO       = funcCallbacks['windowsFileIO']
        self.linuxFileIO         = funcCallbacks['linuxFileIO'] 
        self.customCallback = funcCallbacks['customCallback']

    def removeBreakpoints(self):
        import idc
        
        for bptCount in range(0,idc.GetBptQty()):
            bptAddr = idc.GetBptEA(bptCount)
            
            if idc.DelBpt(bptAddr):
                self.logger.info( "Breakpoint at 0x%x removed." % bptAddr )
                    
    def run(self):
        import idaapi
        import idc
        import logging
        import os
        import sys
        
        from dispatcher.core.structures.Tracer import InputMonitor as InputMonitor
        from dispatcher.core.structures.Tracer.Config.config import ConfigFile as ConfigFile
        from dispatcher.core.structures.Tracer import TargetProcess as TargetProcess
        from dispatcher.core.structures.Tracer.Arch.x86.Windows import WindowsApiCallbacks as WindowsApiCallbacks
        from dispatcher.core.structures.Tracer.Arch.x86.Linux import LinuxApiCallbacks as LinuxApiCallbacks
        from dispatcher.core.structures.Tracer import CustomCallbacks as CustomCallbacks
        
        from dispatcher.core.structures.Tracer.ETDbgHook import ETDbgHook as ETDbgHook

        os_type = ""
        os_arch = ""
        checkInput = ""
        filters = dict()
        bDbg = False
        bLog = False
        
        logfile = ""
        debugger =""
     
        #Get basic information from the file being Debugged
        idainfo = idaapi.get_inf_structure()

        #Get the name of the input file we want to trace
        app_name = idc.GetInputFile()
        print "The input file is %s" % app_name
                
        #Check to see what type of file we're tracing
        #And set up the proper debugger and input monitor
        if idainfo.filetype == idaapi.f_PE:
            print "Windows PE file"
            os_type = "windows"
            debugger = "win32"
            checkInput = InputMonitor.checkWindowsLibs
        
        elif idainfo.filetype == idaapi.f_MACHO:
            print "Mac OSX Macho file"
            os_type = "macosx"
            debugger = "macosx"
            checkInput = InputMonitor.checkMacLibs
        
        elif idainfo.filetype == idaapi.f_ELF:
            print "Linux ELF file"
            os_type = "linux"
            debugger = "linux"
            checkInput = InputMonitor.checkLinuxLibs
        
        else:
            print "Unknown binary, unable to debug"
            sys.exit(1)
            
        #Check the debugged executable if its 32 or 64bit
        if idainfo.is_64bit():
            print "This binary is 64 bit"
            os_arch = "64"
        elif idainfo.is_32bit():
            print "This binary is 32 bit"
            os_arch = "32"
        else:
            print "Bad binary."
            sys.exit(1)
            
        #Get the file type for the executable being debugger
        fileType = idaapi.get_file_type_name()
        print fileType
        
        #Get the root IDA directory in order to locate the config.xml file
        root_dir = idc.GetIdaDirectory() + "\\plugins\\"
        configFile = root_dir + "\dispatcher\core\structures\Tracer\Config\config.xml"
        print configFile
        
        #Call ConfigFile to grab all configuration information from the config.xml file
        config = ConfigFile(app_name,os_type,os_arch,configFile)
        
        #False =>Use local debugger, True =>Use remote debugger
        try:
            path  = config.getPath()
            application = config.getApplication()
            args  = config.getArgs()
            sdir  = config.getSdir()
            host  = config.getHost()
            _pass = config.getPass()
            _debugger = config.getDebugger()
            
            if _debugger is not None:
                debugger = _debugger
            
            port  = int(config.getPort())
            
            bDbg = config.getDebugFlag()=="True"
            bLog = config.getLoggingFlag()=="True"
            remote = config.getRemote()=="True"
            
            fileFilter = config.getFileFilter()
            if fileFilter is not None:
                filters['file'] = fileFilter
                
            networkFilter = config.getNetworkFilter()
            if networkFilter is not None:
                filters['network'] = networkFilter
            
        except:
            print "Cannot run this executable."
            print "Please make sure it is added to the path and config.xml file."
            sys.exit(1)
            
        filePath = os.path.splitext(config.getOutputPath())
        app = os.path.splitext(app_name)
        self.tracefile = filePath[0] + "_" + app[0] + filePath[1]
        """
        bFileExist = os.path.exists(self.tracefile)
        if bFileExist:
            self.tracefile = self.tracefile + "1"
        """
        logfile = filePath[0] + "_log_" +app[0] + ".log"
        
        self.logger = logging.getLogger('IDATrace')
        
        logging.basicConfig(filename=logfile,
                                    filemode='w',
                                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                                    datefmt='%H:%M:%S',
                                    level=logging.INFO)
        
        self.logger.info( "The application is %s" % app_name )
        
        print logfile
        
        print "Using debugger %s" % debugger
        
        if bDbg:
            self.logger.setLevel(logging.DEBUG)
            print "Logging at debug level"
        
        if bLog:
            print "Logging turned on."
            self.logger.disabled = False
        else:
            print "Logging turned off."
            self.logger.disabled = True

        targetProcess = TargetProcess.TargetProcess(app_name,os_arch,os_type,bDbg,self.tracefile,checkInput)
   
        if idaapi.dbg_is_loaded():
            self.logger.info( "The debugger is loaded, lets try to stop it." )
            bStop = idc.StopDebugger()
            
            if bStop:
                self.logger.info( "Stopped debugger." )
        
                try:    
                    if EThook:
                        self.logger.info("Removing previous hook ...")
                        EThook.unhook()
                except:
                    pass
                    
            else:
                self.logger.info( "Cannot stop debugger." )
                sys.exit(1)
        
        #Use the win32 debugger as our debugger of choice
        #You can can between these debuggers: win32, linux, mac
        idc.LoadDebugger(debugger,remote)
        
        if debugger == "windbg":
            idc.ChangeConfig("MODE=1")
        
        #Set the process parameters, dont know if this actually worked (Should test it)
        idc.SetInputFilePath(path)
        
        idaapi.set_process_options(application,args,sdir,host,_pass,port)
        
        self.removeBreakpoints()
        
        EThook = ETDbgHook(targetProcess,self.logger)
        EThook.hook()
        EThook.steps = 0
        
        if os_type == "macosx":
            print "Setting MacOsxApiCallbacks"
            """
            TODO: XZL
            MacOSXApiCallbacks.macFileIO.SetDebuggerInstance(EThook)
            MacOSXApiCallbacks.macFileIO.SetFilters(filters)
            """
        elif os_type == "windows":
            print "Setting WindowsApiCallbacks"
            self.windowsFileIO.SetDebuggerInstance(EThook)
            self.windowsFileIO.SetFilters(filters)
            self.windowsFileIO.SetLoggerInstance(self.logger)
            
        elif os_type == "linux":
            print "Setting LinuxsApiCallbacks"
            self.linuxFileIO.SetDebuggerInstance(EThook)
            self.linuxFileIO.SetFilters(filters)
            self.linuxFileIO.SetLoggerInstance(self.logger)
            
        customBreakpoints = config.getCustomBreakpoints()
        
        if len(customBreakpoints) > 0:
            self.customCallback.SetDebuggerInstance(EThook)
            self.customCallback.SetFilters(filters)
            
            for breakPoint, callBack in customBreakpoints.items():
                idc.AddBpt(breakPoint)
                idc.SetBptCnd(breakPoint,callBack)
        else:
            print "No custom breakpoints."
            
        self.logger.info("Starting to trace..please wait...")
        idaapi.run_to(idaapi.cvar.inf.maxEA)
        
