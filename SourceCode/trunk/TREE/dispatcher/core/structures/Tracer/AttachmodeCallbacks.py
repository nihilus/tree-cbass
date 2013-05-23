from dispatcher.core.DebugPrint import dbgPrint, Print

class AttachmodeFunctions(object):
    def __init__(self):
        import logging
        
        self.logger = logging.getLogger('IDATrace')
        self.debuggerInstance = None
        self.filter = None
    
    def SetLoggerInstance(self,logger):
        self.logger = logger
        
    def SetDebuggerInstance(self,dbgHook):
        self.debuggerInstance = dbgHook

    def SetFilters(self,_filter):
        self.filter = _filter
        
    def startTrace(self):
        import idaapi
        
        self.logger.info("startTrace called")
        self.debuggerInstance.startTrace()
    
    def stopTrace(self):
        import idaapi
        
        self.logger.info("stopTrace called")
        self.debuggerInstance.stopTrace()
