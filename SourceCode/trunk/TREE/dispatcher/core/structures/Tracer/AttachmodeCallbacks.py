from dispatcher.core.DebugPrint import dbgPrint, Print

class AttachmodeFunctions(object):
    def __init__(self):
        import logging
        
        self.logger = logging.getLogger('IDATrace')
        self.debuggerInstance = None
        self.filter = None
    
    def startTrace(self):
        import idaapi
        
        self.logger.info("startTrace called")
        idaapi.request_step_into()
        idaapi.run_requests()
    
    def stopTrace(self):
        import idaapi
        
        self.logger.info("stopTrace called")
        idaapi.dbg_process_detach()
        idaapi.run_requests()