# TREE - Taint-enabled Reverse Engineering Environment 
# Copyright (c) 2013 Battelle BIT Team - Nathan Li, Xing Li, Loc Nguyen
#
# All rights reserved.
#
# For detailed copyright information see the file license.txt in the IDA PRO plugins folder
#---------------------------------------------------------------------
# DebugPrint.py - Provides debug messages to the IDA Pro console
#---------------------------------------------------------------------

class DebugPrint:
    """
    The DebugPrint class is a configurable class to turn on/off debug messages.
    The flags are in settings.ini
    """
    
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
    """
    Based on the settings in settings.ini
    the Print function with print messages to the IDA output console if debugging is turned on.
    """
    from dispatcher.core.DebugPrint import dbgPrint

    if dbgPrint.dbgFlag:
        print string