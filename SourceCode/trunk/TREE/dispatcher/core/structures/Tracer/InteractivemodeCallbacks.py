from dispatcher.core.DebugPrint import dbgPrint, Print
import logging

class InteractivemodeFunctions(object):
    def __init__(self):
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
        self.logger.info("startTrace called")
        self.debuggerInstance.startTrace()
    
    def stopTrace(self):
        self.logger.info("stopTrace called")
        self.debuggerInstance.stopTrace()