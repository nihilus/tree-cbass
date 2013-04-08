import xml.etree.ElementTree as ET

class TraceConfig:
    def __init__(self,in_file):
        tree = ET.parse(in_file)
        self.root = tree.getroot()
        
    def setProcess(self, app_name):
        self.outputPath = self.root.find("output/path").text
        self.Debug = self.root.find('Debug').text
        self.Logging = self.root.find('Logging').text
        self.getProcess(self.root, app_name)
        
    def getMembers(self):
        tempdict = dict()
        tempdict['application'] = self.application
        tempdict['os'] = self.os
        tempdict['arch'] = self.arch
        tempdict['path'] = self.path
        tempdict['args'] = self.args
        tempdict['sdir'] = self.sdir
        tempdict['remote'] = self.remote
        tempdict['host'] = self.host
        tempdict['_pass'] = self._pass
        tempdict['port'] = self.port
        tempdict['fileFilter'] = self.fileFilter
        tempdict['networkFilter'] = self.networkFilter
        return tempdict
    
    def getMemberCount(self):
        return 9 + len(self.fileFilter) + len(self.networkFilter)
    
    def getDebugFlag(self):
        return self.Debug
    
    def getLoggingFlag(self):
        return self.Logging
    
    def getOsType(self):
        return self.os
    
    def getArchType(self):
        return self.arch
    
    def getApplication(self):
        return self.application
    
    def getProcess(self,root,app_name):
        
        for proc in root.findall('process'):
 
            if proc.attrib['name'] == app_name:
                self.os = proc.attrib['OS']
                self.arch = proc.attrib['Arch']
                
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
                if _input.find('debugger') is not None:
                    self.debugger = _input.find('debugger').text
                
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
            
    def writeToFile(self, f):
        self.root.write(f, pretty_print=False)
    
if __name__ == '__main__':
    
    config = ConfigFile('hexedit.exe')
    print "Arch: " + config.getArchType()
    print "OS Type: " + config.getOsType()
    print "Application: " + config.getApplication()
    print "Input path: " +config.getPath()
    print "Input parameters: %s" % config.getArgs()
    print "Input base directory: " + config.getSdir()
    print "Remote debugging host: %s" %config.getHost()
    print config.getRemote()=="True"
    print "Remote password: %s" % config.getPass()
    print "Remote debugging port: %s" % config.getPort()
    print config.getFileFilter()
    print config.getNetworkFilter()
    print "Output path: %s" % config.getOutputPath()
    print config.getDebugFlag()
    print config.getLoggingFlag()

    