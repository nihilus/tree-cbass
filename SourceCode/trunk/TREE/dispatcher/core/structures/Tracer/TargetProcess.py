#---------------------------------------------------------------------
# IDA debug based Execution Trace(ET) callback routines
#
# Version: 1 
# Author: Nathan Li, Xing Li
# Date: 1/10/2013
#---------------------------------------------------------------------


class TargetProcess():
    def __init__(self,app_name,os_arch,os_type,bDbg,traceFile):

        self.app_name  = app_name
        self.os_arch = os_arch
        self.os_type = os_type
        self.bDbg = bDbg
        self.traceFile = traceFile

    