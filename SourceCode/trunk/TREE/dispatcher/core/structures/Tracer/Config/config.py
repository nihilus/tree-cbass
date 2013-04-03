import xml.etree.ElementTree as ET

class ConfigFile:
    def __init__(self,app_name,os_type,os_arch,configFile):
        print "Searching for configuration with app_name %s, os_type %s, and os_arch %s" % (app_name,os_type,os_arch)

        tree = ET.parse(configFile)
        root = tree.getroot()
        self.customBreakpoints = dict()
        self.getProcess(root,app_name,os_type,os_arch)
        self.outputPath = root.find("output/path").text
        self.Debug = root.find('Debug').text
        self.Logging = root.find('Logging').text
        
    def getDebugFlag(self):
        return self.Debug
    
    def getLoggingFlag(self):
        return self.Logging
    
    def getApplication(self):
        return self.application
    
    def getProcess(self,root,app_name,os_type,os_arch):
        
        for proc in root.findall('process'):
 
            if proc.attrib['name'] == app_name and proc.attrib['OS']== os_type and proc.attrib['Arch']== os_arch:
                
                _input = proc.find('input')
                
                self.networkFilter = []
                self.fileFilter = []

                self.application = _input.find('application').text
                self.path = _input.find('path').text
                #print _input.find('path').text
                self.args = _input.find('args').text
                #print _input.find('args').text
                self.sdir = _input.find('sdir').text
                #print _input.find('sdir').text
                self.remote = _input.find('remote').text
                
                self.host = _input.find('host').text
                #print _input.find('host').text
                self._pass = _input.find('pass').text
                #print _input.find('pass').text
                self.port = _input.find('port').text
                #print _input.find('port').text
                
                _filter = proc.find('filter')
                
                if _filter is not None:
                    
                    if _filter.attrib['type']=="fileIO":
                        
                        for f in _filter:
                            self.fileFilter.append(f.text)
                        #print fileFilter
                        
                    elif _filter.attrib['type']=="networkIO":
                        
                        for n in _filter:
                            self.networkFilter.append(int(n.text))
                        #print networkFilter
                
                customBreakpoints = dict()
                customBreakpoints = proc.find('customBreakpoints')
                
                if customBreakpoints is not None:
                    for customBreakpoint in customBreakpoints:
                        bp = int(customBreakpoint.attrib['breakpoint'],16)
                        cb = customBreakpoint.attrib['callback']
    
                        self.customBreakpoints[bp] = cb
                    
                if _input.find('debugger') is None:
                    self.debugger = None
                else:
                    self.debugger = _input.find('debugger').text

    def getCustomBreakpoints(self):
        return self.customBreakpoints
    
    def getOutputPath(self):
        return self.outputPath 

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
    
if __name__ == '__main__':

    config = ConfigFile('shimgvw.dll','windows','32','config.xml')
    print "Application: " + config.getApplication()
    print "Input path: " +config.getPath()
    print "Input parameters: %s" % config.getArgs()
    print "Input base directory: " + config.getSdir()
    print "Remote debugging host: %s" %config.getHost()
    print config.getRemote()=="True"
    print "Remote password: %s" % config.getPass()
    print "Remote debugging port: %s" % config.getPort()
    print "Debugger is %s" % config.getDebugger()
    
    for k,v in config.getCustomBreakpoints().items():
        print k,v
        
    print config.getFileFilter()
    print config.getNetworkFilter()
    print "Output path: %s" % config.getOutputPath()
    print config.getDebugFlag()
    print config.getLoggingFlag()

    