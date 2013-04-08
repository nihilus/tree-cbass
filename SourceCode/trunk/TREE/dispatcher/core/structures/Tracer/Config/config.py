import xml.etree.ElementTree as ET
                
class ProcessConfig:
    def __init__(self):
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
        self.configFile = configFile
    
    def write(self,process):
        tree = ET.parse(self.configFile)
        root = tree.getroot()
        
    def read(self,app_name,os_type,os_arch):
        tree = ET.parse(self.configFile)
        root = tree.getroot()

        self.processConfig = ProcessConfig()
        if self.getProcessConfig(root,app_name,os_type,os_arch) is False:
            self.processConfig = None
            
        self.outputPath = root.find("output/path").text
        self.Debug = root.find('Debug').text
        self.Logging = root.find('Logging').text
        
    def getOutputPath(self):
        return self.outputPath
    
    def getDebugFlag(self):
        return self.Debug
    
    def getLoggingFlag(self):
        return self.Logging
    
    def getProcessConfig(self,root,app_name,os_type,os_arch):
        
        for proc in root.findall('process'):
 
            if proc.attrib['name'] == app_name and proc.attrib['OS']== os_type and proc.attrib['Arch']== os_arch:
                
                _input = proc.find('input')
                
                self.processConfig.networkFilter = []
                self.processConfig.fileFilter = []

                self.processConfig.application = _input.find('application').text
                self.processConfig.path = _input.find('path').text
                #print _input.find('path').text
                self.processConfig.args = _input.find('args').text
                #print _input.find('args').text
                self.processConfig.sdir = _input.find('sdir').text
                #print _input.find('sdir').text
                self.processConfig.remote = _input.find('remote').text
                
                self.processConfig.host = _input.find('host').text
                #print _input.find('host').text
                self.processConfig._pass = _input.find('pass').text
                #print _input.find('pass').text
                self.processConfig.port = _input.find('port').text
                #print _input.find('port').text
                
                _filter = proc.find('filter')
                
                if _filter is not None:
                    
                    if _filter.attrib['type']=="fileIO":
                        
                        for f in _filter:
                            self.processConfig.fileFilter.append(f.text)
                        #print fileFilter
                        
                    elif _filter.attrib['type']=="networkIO":
                        
                        for n in _filter:
                            self.processConfig.networkFilter.append(int(n.text))
                        #print networkFilter
                
                customBreakpoints = dict()
                customBreakpoints = proc.find('customBreakpoints')
                
                if customBreakpoints is not None:
                    for customBreakpoint in customBreakpoints:
                        bp = int(customBreakpoint.attrib['breakpoint'],16)
                        cb = customBreakpoint.attrib['callback']
    
                        self.processConfig.customBreakpoints[bp] = cb
                    
                if _input.find('debugger') is None:
                    self.processConfig.debugger = None
                else:
                    self.processConfig.debugger = _input.find('debugger').text
            
                return True
        
        return False
    
if __name__ == '__main__':

    config = ConfigFile('shimgvw.dll','windows','32','config.xml')
    processConfig = config.processConfig
    
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

    