class DebugPrint:
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state
        
    def setDbgFlag(self,flag):
        self.__dbgFlag = flag
    
    def getDbgFlag(self):
        return getattr(self, '__dbgFlag', None)

    dbgFlag = property(getDbgFlag, setDbgFlag)
    

dbgPrint = DebugPrint()

def Print(string):
    from dispatcher.core.DebugPrint import dbgPrint

    if dbgPrint.dbgFlag:
        print string