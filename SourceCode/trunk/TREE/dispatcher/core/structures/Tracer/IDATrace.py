#---------------------------------------------------------------------
# IDA debug based Execution Trace(ET) callback routines
#
# Version: 1 
# Author: Nathan Li, Xing Li
# Date: 1/10/2013
#---------------------------------------------------------------------
from dispatcher.core.DebugPrint import dbgPrint, Print

class IDATrace():
    
    def __init__(self,funcCallbacks):
        """
        This is the start of the debugger.
        """
        import idaapi
        
        self.windowsFileIO       = funcCallbacks['windowsFileIO']
        self.windowsNetworkIO    = funcCallbacks['windowsNetworkIO']
        self.linuxFileIO         = funcCallbacks['linuxFileIO'] 
        self.customCallback      = funcCallbacks['customCallback']   
        
        self.config = None
        (processName, osType, osArch) = self.getProcessInfo()
        self.processConfig = self.createProcessConfig(processName, osType, osArch)
        
        try:
            taintStart_ctx
    
            if idaapi.del_hotkey(taintStart_ctx):
                Print ("Hotkey taint start hotkey unregistered!")
                del taintStart_ctx
            else:
                Print("Failed to delete taint start hotkey!")
        except:
            taintStart_ctx = idaapi.add_hotkey("Shift-A", self.taintStart)
            if taintStart_ctx is None:
                print("Failed to register taint start hotkey!")
                del taintStart_ctx
            else:
                Print ("Hotkey taint start registered!")
                
        try:
            taintStop_ctx
    
            if idaapi.del_hotkey(taintStop_ctx):
                Print ("Hotkey taint stop hotkey unregistered!")
                del taintStop_ctx
            else:
                Print("Failed to delete taint stop hotkey!")
        except:
            taintStop_ctx = idaapi.add_hotkey("Shift-Z", self.taintStop)
            if taintStop_ctx is None:
                print("Failed to register taint stop hotkey!")
                del taintStop_ctx
            else:
                Print ("Hotkey taint stop registered!")
                
        try:
            ex_addmenu_item_ctx
            idaapi.del_menu_item(ex_addmenu_item_ctx)
            print("Menu removed")
            del ex_addmenu_item_ctx
        except:
            ex_addmenu_item_ctx = idaapi.add_menu_item("Edit/", "X", "", 0, self.clearTaintSettings, tuple("Clear Taint"))
            if ex_addmenu_item_ctx is None:
                print("Failed to add menu!")
                del ex_addmenu_item_ctx
            else:
                print("Menu added successfully. Run the script again to delete the menu")
        

    def clearTaintSettings(self,*args):
        print("Callback called!")
        return 1

    def taintStart(self):
        import idc
        print("Taint Start pressed!")
        ea = idc.ScreenEA()
        #Set the start taint to green
        idc.SetColor(ea,idc.CIC_ITEM,0x208020)
        print idc.GetDisasm(ea)
    
    def taintStop(self):
        import idc
        print("Taint Stop pressed!")
        ea = idc.ScreenEA()
        #Set the stop taint to red
        idc.SetColor(ea,idc.CIC_ITEM,0x2020c0)
        print idc.GetDisasm(ea)
        
    def attach(self,processConfig):
        import idaapi
        import idc
        import logging
        import os
        import sys
        
        from dispatcher.core.structures.Tracer import InputMonitor as InputMonitor
        from dispatcher.core.structures.Tracer import TargetProcess as TargetProcess
        from dispatcher.core.structures.Tracer.Arch.x86.Windows import WindowsApiCallbacks as WindowsApiCallbacks
        from dispatcher.core.structures.Tracer.Arch.x86.Linux import LinuxApiCallbacks as LinuxApiCallbacks
        from dispatcher.core.structures.Tracer import CustomCallbacks as CustomCallbacks
        from dispatcher.core.structures.Tracer.ETDbgHook import ETDbgHook as ETDbgHook
            
        filters = dict()
        bDbg = False
        if self.config.Debug == "True":
            bDbg = True
        else:
            bDbg = False
            
        bLog = False

        if self.config.Logging == "True":
            bLog = True
        else:
            bLog = False
            
        logfile = ""

        app_name = processConfig.getName()
        os_type  = processConfig.getOsType()
        os_arch  = processConfig.getOsArch()
        
        path  = processConfig.getPath()

        application = processConfig.getApplication()
        args  = processConfig.getArgs()
        sdir  = processConfig.getSdir()

        debugger = processConfig.getDebugger()
        remote = processConfig.getRemote()=="True"
        
        if remote:
            port  = int(processConfig.getPort())
            host  = processConfig.getHost()
            _pass = processConfig.getPass()
        else:
            port = 0
            host = ""
            _pass = ""
            
        fileFilter = processConfig.getFileFilter()
        networkFilter = processConfig.getNetworkFilter()

        filePath = os.path.splitext(self.config.getOutputPath())
        app = os.path.splitext(app_name)
        self.tracefile = filePath[0] + "_" + app[0] + filePath[1]

        logfile = filePath[0] + "_log_" +app[0] + ".log"
        
        self.logger = logging.getLogger('IDATrace')
        
        logging.basicConfig(filename=logfile,
                                    filemode='w',
                                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                                    datefmt='%H:%M:%S',
                                    level=logging.INFO)
        
        self.logger.info( "The application is %s" % app_name )
        
        Print( logfile )
        
        Print( "Using debugger %s" % debugger )
        
        if bDbg:
            self.logger.setLevel(logging.DEBUG)
            Print ("Logging at debug level" )
        
        if bLog:
            Print( "Logging turned on." )
            self.logger.disabled = False
        else:
            Print( "Logging turned off." )
            self.logger.disabled = True

        targetProcess = TargetProcess.TargetProcess(app_name,os_arch,os_type,bDbg,self.tracefile)
   
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
        """
        if debugger == "windbg":
            idc.ChangeConfig("MODE=1")
        """
        #Set the process parameters, dont know if this actually worked (Should test it)
        #idc.SetInputFilePath(path)
        
        idaapi.set_process_options(application,args,sdir,host,_pass,port)
        
        self.removeBreakpoints()
        
        EThook = ETDbgHook(targetProcess,self.logger)
        EThook.hook()
        EThook.steps = 0
            
        process_name = processConfig.getApplication()
        PID = self.getRunningProcesses(process_name)

        self.logger.info("Attaching to %s to generate a trace..please wait..." % process_name)
                
        if PID == -1:
            idc.Warning("%s is not running.  Please start the process first." % process_name)
        else:
            ret = idc.AttachProcess(PID, -1)
            """
            if ret != -1:
                idc.Warning("Error attaching to %s" % process_name)
            """
            
        
    def getRunningProcesses(self,process_name):
        import idc
    
        numOfProcessesRunning = idc.GetProcessQty()
        Print ("Found %d running processes" % (numOfProcessesRunning))
        
        Print("Searching for %s" % process_name )
        
        for i in range(numOfProcessesRunning):
            Print("Process ID=[%d], %s" % (idc.GetProcessPid(i),idc.GetProcessName(i) ))
            
            if process_name in idc.GetProcessName(i):
                return idc.GetProcessPid(i)

            

        return -1

    def removeBreakpoints(self):
        import idc
        
        for bptCount in range(0,idc.GetBptQty()):
            bptAddr = idc.GetBptEA(bptCount)
            
            if idc.DelBpt(bptAddr):
                self.logger.info( "Breakpoint at 0x%x removed." % bptAddr )
    
    def getProcessInfo(self):
        import idaapi
        import idc
        
        #Get basic information from the file being Debugged
        idainfo = idaapi.get_inf_structure()

        #Get the name of the input file we want to trace
        app_name = idc.GetInputFile()

        Print ("The input file is %s" % app_name )

        #Check to see what type of file we're tracing
        #And set up the proper debugger and input monitor
        if idainfo.filetype == idaapi.f_PE:
            Print ("Windows PE file" )
            os_type = "windows"
        
        elif idainfo.filetype == idaapi.f_MACHO:
            Print ("Mac OSX Macho file")
            os_type = "macosx"
            #debugger = "macosx"
            #checkInput = InputMonitor.checkMacLibs
        
        elif idainfo.filetype == idaapi.f_ELF:
            Print ("Linux ELF file")
            os_type = "linux"
            #debugger = "linux"
            #checkInput = InputMonitor.checkLinuxLibs
        
        else:
            Print ("Unknown binary, unable to debug")
            return None
            
        #Check the debugged executable if its 32 or 64bit
        if idainfo.is_64bit():
            Print("This binary is 64 bit")
            os_arch = "64"
        elif idainfo.is_32bit():
            Print( "This binary is 32 bit" )
            os_arch = "32"
        else:
            Print( "Bad binary." )
            return None
            
        #Get the file type for the executable being debugger
        fileType = idaapi.get_file_type_name()
        Print( fileType )
        
        return (app_name,os_type,os_arch)
    
    def getProcessConfig(self):
        return self.processConfig
    
    def setProcessConfig(self,processConfig):
        self.config.write(processConfig)
    
    def createProcessConfig(self,name,osType,osArch):
        import idc
        from dispatcher.core.structures.Tracer.Config.config import ConfigFile as ConfigFile
        from dispatcher.core.structures.Tracer.Config.config import ProcessConfig as ProcessConfig
        
        #Get the root IDA directory in order to locate the config.xml file
        root_dir = idc.GetIdaDirectory() + "\\plugins\\"
        configFile = root_dir + "\dispatcher\core\structures\Tracer\Config\config.xml"
        Print( configFile )
        
        #Call ConfigFile to grab all configuration information from the config.xml file
        self.config = ConfigFile(configFile)
        processConfig = self.config.read(name,osType,osArch)
        
        if processConfig is None:
            processConfig = ProcessConfig()
            processConfig.name = name
            processConfig.osType = osType
            processConfig.osArch = osArch
            processConfig.application = name
            processConfig.path = name
            processConfig.port = "0"
            processConfig.remote = "False"
            
            if osType == "macosx":
                processConfig.debugger = "macosx"
            elif osType == "windows":
                processConfig.debugger = "win32"
            elif osType == "linux":
                processConfig.debugger = "linux"
            
            self.config.write(processConfig)
            Print( "Saving new process configuration" )
            
        return processConfig
        
    def run(self,processConfig):
        import idaapi
        import idc
        import logging
        import os
        import sys
        
        from dispatcher.core.structures.Tracer import InputMonitor as InputMonitor
        from dispatcher.core.structures.Tracer import TargetProcess as TargetProcess
        from dispatcher.core.structures.Tracer.Arch.x86.Windows import WindowsApiCallbacks as WindowsApiCallbacks
        from dispatcher.core.structures.Tracer.Arch.x86.Linux import LinuxApiCallbacks as LinuxApiCallbacks
        from dispatcher.core.structures.Tracer import CustomCallbacks as CustomCallbacks
        from dispatcher.core.structures.Tracer.ETDbgHook import ETDbgHook as ETDbgHook
            
        filters = dict()
        bDbg = False
        if self.config.Debug == "True":
            bDbg = True
        else:
            bDbg = False
            
        bLog = False

        if self.config.Logging == "True":
            bLog = True
        else:
            bLog = False
            
        logfile = ""

        app_name = processConfig.getName()
        os_type  = processConfig.getOsType()
        os_arch  = processConfig.getOsArch()
        
        path  = processConfig.getPath()

        application = processConfig.getApplication()
        args  = processConfig.getArgs()
        sdir  = processConfig.getSdir()

        debugger = processConfig.getDebugger()
        remote = processConfig.getRemote()=="True"
        
        if remote:
            port  = int(processConfig.getPort())
            host  = processConfig.getHost()
            _pass = processConfig.getPass()
        else:
            port = 0
            host = ""
            _pass = ""
            
        fileFilter = processConfig.getFileFilter()
        networkFilter = processConfig.getNetworkFilter()

        filePath = os.path.splitext(self.config.getOutputPath())
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
        
        Print( logfile )
        
        Print( "Using debugger %s" % debugger )
        
        if bDbg:
            self.logger.setLevel(logging.DEBUG)
            Print ("Logging at debug level" )
        
        if bLog:
            Print( "Logging turned on." )
            self.logger.disabled = False
        else:
            Print( "Logging turned off." )
            self.logger.disabled = True

        targetProcess = TargetProcess.TargetProcess(app_name,os_arch,os_type,bDbg,self.tracefile)
   
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
            Print( "Setting MacOsxApiCallbacks" )
            checkInput = InputMonitor.checkMacLibs
            """
            TODO: XZL
            MacOSXApiCallbacks.macFileIO.SetDebuggerInstance(EThook)
            MacOSXApiCallbacks.macFileIO.SetFilters(filters)
            """
        elif os_type == "windows":
            Print( "Setting WindowsApiCallbacks" )
            
            EThook.checkInput =  InputMonitor.checkWindowsLibs
            
            if fileFilter is not None:
                Print( "Setting file filters for windows" )
                filters['file'] = fileFilter
                EThook.bCheckFileIO = True
                self.windowsFileIO.SetDebuggerInstance(EThook)
                self.windowsFileIO.SetFilters(filters)
                self.windowsFileIO.SetLoggerInstance(self.logger)
            
            if networkFilter is not None:
                Print( "Setting network filters for windows" )
                filters['network'] = networkFilter
                EThook.bCheckNetworkIO = True
                self.windowsNetworkIO.SetDebuggerInstance(EThook)
                self.windowsNetworkIO.SetFilters(filters)
                self.windowsNetworkIO.SetLoggerInstance(self.logger)

        elif os_type == "linux":
            Print( "Setting LinuxsApiCallbacks" )
            EThook.checkInput =  InputMonitor.checkLinuxLibs
            
            if fileFilter is not None:
                filters['file'] = fileFilter
                EThook.bCheckFileIO = True
                self.linuxFileIO.SetDebuggerInstance(EThook)
                self.linuxFileIO.SetFilters(filters)
                self.linuxFileIO.SetLoggerInstance(self.logger)
            
            if networkFilter is not None:
                filters['network'] = networkFilter
                EThook.bCheckNetworkIO = True
                self.linuxNetworkIO.SetDebuggerInstance(EThook)
                self.linuxNetworkIO.SetFilters(filters)
                self.linuxNetworkIO.SetLoggerInstance(self.logger)
            
        customBreakpoints = processConfig.getCustomBreakpoints()
        
        if len(customBreakpoints) > 0:
            self.customCallback.SetDebuggerInstance(EThook)
            self.customCallback.SetFilters(filters)
            
            for breakPoint, callBack in customBreakpoints.items():
                idc.AddBpt(breakPoint)
                idc.SetBptCnd(breakPoint,callBack)
        else:
            Print( "No custom breakpoints." )
            
        self.logger.info("Starting to trace..please wait...")
        idaapi.run_to(idaapi.cvar.inf.maxEA)
        
