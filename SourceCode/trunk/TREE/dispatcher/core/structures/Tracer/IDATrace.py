# TREE - Taint-enabled Reverse Engineering Environment 
# Copyright (c) 2013 Battelle BIT Team - Nathan Li, Xing Li, Loc Nguyen
#
# All rights reserved.
#
# For detailed copyright information see the file license.txt in the IDA PRO plugins folder
#---------------------------------------------------------------------
# IDATrace.py - IDA pro Tracing
#---------------------------------------------------------------------

from dispatcher.core.DebugPrint import dbgPrint, Print

import idc
import idaapi
import logging

class IDATrace():
    
    def __init__(self,funcCallbacks):
        """
        This is the start of the debugger.
        """
        import os
        
        from dispatcher.core.Util import ConfigReader, unique_file_name
        from dispatcher.core.structures.Tracer.Config.config import ConfigFile as ConfigFile
        
        #Get the root IDA directory in order to locate the config.xml file
        root_dir = os.path.join( idc.GetIdaDirectory() ,"plugins")
        ini_path = os.path.join(root_dir,"settings.ini")

        configReader = ConfigReader()
        configReader.Read(ini_path)
        
       # self.removeBreakpoints()

        self.windowsFileIO       = funcCallbacks['windowsFileIO']
        self.windowsNetworkIO    = funcCallbacks['windowsNetworkIO']
        self.linuxFileIO         = funcCallbacks['linuxFileIO'] 
                
        configFile = configReader.configFile
        
        #Print( configFile )
        #Call ConfigFile to grab all configuration information from the config.xml file
        self.config = ConfigFile(configFile)
        
        (processName, osType, osArch) = self.getProcessInfo()

        self.processConfig = self.createProcessConfig(processName, osType, osArch)

        filePath = os.path.splitext(configReader.traceFile)
        processBasename = os.path.splitext(processName)
        
        self.tracefile = filePath[0] + "_" + processBasename[0] + filePath[1]
        self.tracefile = unique_file_name(self.tracefile)
        Print(self.tracefile)
        
        traceFileName = os.path.splitext(self.tracefile)
        self.treeTracefile = traceFileName[0] + ".idb"
        
        self.logger = None
        logfile = traceFileName[0] + ".log"
        
        self.initLogging(logfile,configReader.logging,configReader.debugging)
 
        print "IDATrace init called."    
        
    def initLogging(self,logfile,bLog,bDbg):

        self.logger = logging.getLogger('IDATrace')
        
        logging.basicConfig(filename=logfile,
                                    filemode='w',
                                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                                    datefmt='%H:%M:%S',
                                    level=logging.INFO)

        if bLog:
            Print("Logging is turned on.")
            self.logger.disabled = False
        else:
            Print("Logging is turned off.")
            self.logger.disabled = True
        
        if bDbg:
            Print("Log Debug mode is turned on.")
            self.logger.setLevel(logging.DEBUG)

    def getRunningProcesses(self,process_name):

        numOfProcessesRunning = idc.GetProcessQty()
        Print ("Found %d running processes" % (numOfProcessesRunning))
        
        Print("Searching for %s" % process_name )
        
        for i in range(numOfProcessesRunning):
            #Print("Process ID=[%d], %s" % (idc.GetProcessPid(i),idc.GetProcessName(i) ))
            
            if process_name in idc.GetProcessName(i):
                return idc.GetProcessPid(i)

        return -1
               
    def getProcessInfo(self):

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
        import os

        from dispatcher.core.structures.Tracer.Config.config import ProcessConfig as ProcessConfig
        
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
    
    def setDebuggerOptions(self,processConfig,interactiveMode):
        
        from dispatcher.core.structures.Tracer.ETDbgHook import ETDbgHook as ETDbgHook
 
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
            
        #Use the win32 debugger as our debugger of choice
        #You can can between these debuggers: win32, linux, mac
        idc.LoadDebugger(debugger,remote)
        
        #Set the process parameters, dont know if this actually worked (Should test it)
        idc.SetInputFilePath(path)
        
        idaapi.set_process_options(application,args,sdir,host,_pass,port)

        EThook = ETDbgHook(self.tracefile,self.treeTracefile,self.logger)
        EThook.hook()
        EThook.steps = 0
        
        return EThook
             
    def run(self,processConfig):

        from dispatcher.core.structures.Tracer import InputMonitor as InputMonitor
        from dispatcher.core.structures.Tracer.Arch.x86.Windows import WindowsApiCallbacks as WindowsApiCallbacks
        from dispatcher.core.structures.Tracer.Arch.x86.Linux import LinuxApiCallbacks as LinuxApiCallbacks

        EThook = self.setDebuggerOptions(processConfig,False)
        filters = dict()
        
        os_type = processConfig.getOsType()
        fileFilter = processConfig.getFileFilter()
        networkFilter = processConfig.getNetworkFilter()

        if os_type == "macosx":
            Print( "Setting MacOsxApiCallbacks" )
            EThook.checkInput  = InputMonitor.checkMacLibs

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
   
        self.logger.info("Starting to trace..please wait...")
        idaapi.run_to(idaapi.cvar.inf.maxEA)
    
   