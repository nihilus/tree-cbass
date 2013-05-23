'''
   This is the script for TREE initial taint marking.  
 * @author Nathan Li
 * 
 */

'''
import sys
import os
from optparse import OptionParser
import logging
import struct
from Taint import Taint, INPUT_TAINT,REGISTER_TAINT,MEMORY_TAINT,BRANCH_TAINT 
from TraceParser import TraceReader, IDATextTraceReader, PinTraceReader
from TaintTracker import TaintTracker

class TaintMarker(object):
    def __init__(self, TP):
        self.taintTracker = TP 

    def SetInputTaint(self, INRecord):
        address = INRecord.currentInputAddr
        for i in range(INRecord.currentInputSize):
            if(address+i in self.taintTracker.dynamic_taint):
                self.taintTracker.dynamic_taint[address+i].terminateTaint(INRecord.sequence,INRecord.callingThread)
            taint = Taint(INPUT_TAINT,address+i,INRecord.sequence,INRecord.callingThread, INRecord.inputFunction,True)
            taint.setInputFunctionCaller(INRecord.functionCaller)
            Taint.uid2Taint[taint.tuid]= taint
            self.taintTracker.dynamic_taint[address+i] = taint
            #print("Input Taint: %s" %(taint.taint_simple()))
            
    def setInteractiveTaint(self,taintSource):
        split = taintSource.split("_")
        if(split[0]=="mem"):
            address = int(split[1][2:],16)
            size = int(split[2])
            for i in range(size):
                if(address+i in self.dynamic_taint):
                    self.taintTracker.dynamic_taint[address+i].terminateTaint(INRecord.sequence,INRecord.callingThread)
                taint = Taint(MEMORY_TAINT,address+i,0,0x0, "testInteractive")
                Taint.uid2Taint[taint.tuid]= taint
                self.taintTracker.dynamic_taint[address+i] = taint
                #print("Interactive Taint Source: %s" %(taint.taint_simple()))
        elif (split[0]=="reg"):            
            regName = split[1]
            offset = int(split[2])
            size = int(split[3])
            tid = int(split[4])
            for i in range(size):
                regI = regName +"_"+(str(offset+i)+"_"+str(tid))
                taint = Taint(REGISTER_TAINT,regI, 0,tid,"test interactive reg")
                Taint.uid2Taint[taint.tuid]= taint
                self.taintTracker.dynamic_taint[regI] = taint
                #print("Interactive Taint Source: %s" %(taint.taint_simple()))
        else:
            print ("Wrong Taint")
