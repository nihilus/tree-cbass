import xml.etree.ElementTree as ET
                
class ProcessConfig:
    def __init__(self):
        self.name = None
        self.osType = None
        self.osArch = None
        self.networkFilter = []
        self.fileFilter = []
        self.application = None
        self.path = None
        self.args = None
        self.sdir = None
        self.remote = None
        self.host = None
        self._pass = None
        self.port = None
        self.customBreakpoints= dict()
        self.debugger = None
        
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
        tree = ET.parse(configFile)
        root = tree.getroot()

        self.processTable = dict()
        self.getProcessData(root)
            
        self.outputPath = root.find("output/path").text
        self.Debug = root.find('Debug').text
        self.Logging = root.find('Logging').text
    
    def write(self,app_name,os_type,os_arch):
        pass
        
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
            
            processConfig.host = _input.find('host').text
            #print _input.find('host').text
            processConfig._pass = _input.find('pass').text
            #print _input.find('pass').text
            processConfig.port = _input.find('port').text
            #print _input.find('port').text
            
            _filter = proc.find('filter')
            
            if _filter is not None:
                
                if _filter.attrib['type']=="fileIO":
                    
                    for f in _filter:
                        processConfig.fileFilter.append(f.text)
                    #print fileFilter
                    
                elif _filter.attrib['type']=="networkIO":
                    
                    for n in _filter:
                        processConfig.networkFilter.append(int(n.text))
                    #print networkFilter
            
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
    
    """
    def getProcessConfig(self,root,app_name,os_type,os_arch):
        
        for proc in root.findall('process'):
 
            if proc.attrib['name'] == app_name and proc.attrib['OS']== os_type and proc.attrib['Arch']== os_arch:
                
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
                
                processConfig.host = _input.find('host').text
                #print _input.find('host').text
                processConfig._pass = _input.find('pass').text
                #print _input.find('pass').text
                processConfig.port = _input.find('port').text
                #print _input.find('port').text
                
                _filter = proc.find('filter')
                
                if _filter is not None:
                    
                    if _filter.attrib['type']=="fileIO":
                        
                        for f in _filter:
                            processConfig.fileFilter.append(f.text)
                        #print fileFilter
                        
                    elif _filter.attrib['type']=="networkIO":
                        
                        for n in _filter:
                            processConfig.networkFilter.append(int(n.text))
                        #print networkFilter
                
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
            
                return True
        
        return False
    """
if __name__ == '__main__':

    config = ConfigFile('config.xml')
    
    processConfig = config.read('shimgvw.dll','windows','32')
    print "Application: " + processConfig.getApplication()
    print "Input path: " +processConfig.getPath()
    print "Input parameters: %s" % processConfig.getArgs()
    print "Input base directory: " + processConfig.getSdir()
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

    