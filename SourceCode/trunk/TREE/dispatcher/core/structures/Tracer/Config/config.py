import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element,SubElement

from dispatcher.core.DebugPrint import dbgPrint, Print

class ProcessConfig:
    def __init__(self):
        self.name = ""
        self.osType = ""
        self.osArch = ""
        self.networkFilter = []
        self.fileFilter = []
        self.application = ""
        self.path = ""
        self.args = ""
        self.sdir = ""
        self.remote = ""
        self.host = ""
        self._pass = ""
        self.port = ""
        self.customBreakpoints= dict()
        self.debugger = ""
        self.pin = ""
        
    def getName(self):
        return self.name
    
    def getOsType(self):
        return self.osType
    
    def getOsArch(self):
        return self.osArch
    
    def getApplication(self):
        return self.application
    
    def getArgs(self):
        return self.args
    
    def getPath(self):
        return self.path
    
    def getSdir(self):
        return self.sdir
    
    def getHost(self):
        return self.host
    
    def getPass(self):
        return self._pass
    
    def getRemote(self):
        return self.remote
    
    def getPort(self):
        return self.port
        
    def getPin(self):
        return self.pin
    
    def getCustomBreakpoints(self):
        return self.customBreakpoints
    
    def getDebugger(self):
        return self.debugger
    
    def getFileFilter(self):
        if self.fileFilter is None:
            return None
        else:
            #return file filter
            return self.fileFilter
    
    def getNetworkFilter(self):
        if self.networkFilter is None:
            return None
        else:
            #return network filters
            return self.networkFilter
        
class ConfigFile:
    def __init__(self,configFile):
        self.tree = ET.parse(configFile)
        self.root = self.tree.getroot()

        self.processTable = dict()
        self.getProcessData(self.root)
            
        self.outputPath = self.root.find("output/path").text
        self.Debug = self.root.find('Debug').text
        self.Logging = self.root.find('Logging').text
        self.configFile = configFile
        Print( "Creating a new config object" )
    
    def write(self,processConfig):
        config = self.root
        
        newProcess = Element("process")
        #Before writing or updating the config.xml file, we need to refresh the internal process table
        self.getProcessData(self.root)
        
        if self.processTable.has_key(str(processConfig.getName())+str(processConfig.getOsType())+str(processConfig.getOsArch())):
            Print( "updating an existing configuration" )
            self.update(processConfig)
        else:
            Print( "Adding a new configuration" )
            #adding a new process config
            newProcess.attrib["name"] = processConfig.getName()
            newProcess.attrib["OS"] = processConfig.getOsType()
            newProcess.attrib["Arch"] = processConfig.getOsArch()

            newProcess_input = Element("input")
            
            application = Element("application")
            application.text = processConfig.getApplication()
            newProcess_input.append(application)
            
            path = Element("path")
            path.text = processConfig.getPath()
            newProcess_input.append(path)
            
            args = Element("args")
            args.text = processConfig.getArgs()
            newProcess_input.append(args)
            
            args = Element("sdir")
            args.text = "."
            newProcess_input.append(args)
            
            remote = Element("remote")
            remote.text = "False"
            newProcess_input.append(remote)
            
            pin = Element("pin")
            pin.text = "False"
            newProcess_input.append(pin)
            
            host = Element("host")
            host.text = ""
            newProcess_input.append(host)
    
            _pass = Element("pass")
            _pass.text = ""
            newProcess_input.append(_pass)
            
            port = Element("port")
            port.text = "0"
            newProcess_input.append(port)
            
            debugger = Element("debugger")
            debugger.text = processConfig.getDebugger()
            newProcess_input.append(debugger)
            """
            filter_file = Element("filter")
            filter_file.attrib["type"] = "fileIO"
            filter_file.text = ""
            
            filter_network = Element("filter")
            filter_network.attrib["type"] = "networkIO"
            filter_network.text = ""
            """
            newProcess.append(newProcess_input)
            #newProcess.append(filter_file)
            #newProcess.append(filter_network)
            
            config.append(newProcess)
        
        #self.tree.write("output.xml")
        self.tree.write(self.configFile, "UTF-8")
        
    def read(self,app_name,os_type,os_arch):
        key = app_name+os_type+os_arch
        if self.processTable.has_key(key):
            return self.processTable[key]
        else:
            return None
        
    def getProcessData(self,root):
        for proc in root.findall('process'):
            
            processConfig = ProcessConfig()
            processConfig.name = proc.attrib['name']
            processConfig.osType = proc.attrib['OS']
            processConfig.osArch = proc.attrib['Arch']
                
            _input = proc.find('input')
            
            processConfig.networkFilter = []
            processConfig.fileFilter = []

            processConfig.application = _input.find('application').text
            processConfig.path = _input.find('path').text
            #print _input.find('path').text
            processConfig.args = _input.find('args').text
            #print _input.find('args').text
            processConfig.sdir = _input.find('sdir').text
            #print _input.find('sdir').text
            processConfig.remote = _input.find('remote').text
            
            #
            # For backwards compatability with older configs
            #
            try:
                processConfig.pin = _input.find('pin').text
            except AttributeError:
                processConfig.pin = "False"
            
            processConfig.host = _input.find('host').text
            #print _input.find('host').text
            processConfig._pass = _input.find('pass').text
            #print _input.find('pass').text
            processConfig.port = _input.find('port').text
            #print _input.find('port').text
            
            _filters = proc.findall('filter')
            
            for _filter in _filters:
                
                if _filter.attrib['type']=="fileIO":
                    
                    for f in _filter:
                        #print f.text
                        processConfig.fileFilter.append(f.text)
 
                if _filter.attrib['type']=="networkIO":
                    
                    for n in _filter:
                        #print n.text
                        processConfig.networkFilter.append(n.text)
            
            customBreakpoints = dict()
            customBreakpoints = proc.find('customBreakpoints')
            
            if customBreakpoints is not None:
                for customBreakpoint in customBreakpoints:
                    bp = int(customBreakpoint.attrib['breakpoint'],16)
                    cb = customBreakpoint.attrib['callback']

                    processConfig.customBreakpoints[bp] = cb
                
            if _input.find('debugger') is None:
                processConfig.debugger = None
            else:
                processConfig.debugger = _input.find('debugger').text
            
            key = processConfig.name+processConfig.osType+processConfig.osArch
            
            self.processTable[key] = processConfig
        
    def getOutputPath(self):
        return self.outputPath
    
    def getDebugFlag(self):
        return self.Debug
    
    def getLoggingFlag(self):
        return self.Logging
    
    def update(self,processConfig):
        name   = processConfig.getName()
        osType = processConfig.getOsType()
        osArch = processConfig.getOsArch()
        
        for proc in self.root.findall('process'):
 
            if proc.attrib['name'] == name and proc.attrib['OS']== osType and proc.attrib['Arch']== osArch:
                
                _input = proc.find('input')

                _input.find('application').text = processConfig.getApplication()
                _input.find('path').text = processConfig.getPath()
                _input.find('args').text = processConfig.getArgs()
                _input.find('sdir').text = processConfig.getSdir()
                _input.find('remote').text = processConfig.getRemote()
                _input.find('pin').text = processConfig.getPin()
                _input.find('host').text = processConfig.getHost()
                _input.find('pass').text = processConfig.getPass()
                _input.find('port').text = processConfig.getPort()
                try:
                    _input.find('debugger').text = processConfig.getDebugger()
                except AttributeError:
                    print "entry without debugger attribute"

                _filters = proc.findall('filter')
                
                for _filter in _filters:
                    proc.remove(_filter)
                
                if processConfig.getFileFilter():
                    filter_file = Element("filter")
                    filter_file.attrib["type"] = "fileIO"
                
                    for f in processConfig.getFileFilter():
                        SubElement(filter_file, "fileName").text = f
                        
                    proc.append(filter_file)
                
                if processConfig.getNetworkFilter():
                    filter_network = Element("filter")
                    filter_network.attrib["type"] = "networkIO"
                
                    for n in processConfig.getNetworkFilter():
                        SubElement(filter_network, "port").text = n
                    
                    proc.append(filter_network)
                    
                """
                customBreakpoints = dict()
                customBreakpoints = proc.find('customBreakpoints')
                
                if customBreakpoints is not None:
                    for customBreakpoint in customBreakpoints:
                        bp = int(customBreakpoint.attrib['breakpoint'],16)
                        cb = customBreakpoint.attrib['callback']
    
                        processConfig.customBreakpoints[bp] = cb
                """

if __name__ == '__main__':

    config = ConfigFile('config.xml')
    processConfig = config.read('winVS.exe','windows','32')
    print "Application: " + processConfig.getApplication()
    print "Input path: " +processConfig.getPath()
    print "Input parameters: %s" % processConfig.getArgs()
    #print "Input base directory: " + processConfig.getSdir()
    print "Remote debugging host: %s" %processConfig.getHost()
    print processConfig.getRemote()=="True"
    print "Remote password: %s" % processConfig.getPass()
    print "Remote debugging port: %s" % processConfig.getPort()
    print "Debugger is %s" % processConfig.getDebugger()
    
    for k,v in processConfig.getCustomBreakpoints().items():
        print k,v
        
    print processConfig.getFileFilter()
    print processConfig.getNetworkFilter()
    print "Output path: %s" % config.getOutputPath()
    print config.getDebugFlag()
    print config.getLoggingFlag()
    

    