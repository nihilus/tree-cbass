'''
   This is the script for TREE taint checking. It corellates taint tacking and sink information(exception or other events) to provide
 * the dataflow and relevant instruction slice.
 * @author Nathan Li
 * 
 */

'''
import sys
import os
from optparse import OptionParser
import logging
import struct
from ctypes.util import *
from ctypes import *
import ctypes
import operator
from Taint import Taint, INITIAL_TAINT,REGISTER_TAINT,MEMORY_TAINT,BRANCH_TAINT 
from TraceParser import TraceReader, IDATextTraceReader, PinTraceReader
from x86Decoder import x86Decoder, instDecode, IMMEDIATE, REGISTER,MEMORY, WINDOWS, LINUX
from x86ISA import X86ISA
#Trace type enumeration
IDA = 0
PIN = 1

class TaintChecker(object):
    def __init__(self, TP):
        self.taintTracker = TP
        self.bDebug = False

    def TaintCheckTargets(self, instInfo, instRec):
        sDbg = "Taint Check Sink %s at seq = %d:\n" %(instInfo.attDisa, instRec.currentInstSeq)
        if (self.bDebug == True):
            print ("%s" %sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        bTaint = 0
        
        if (instInfo.inst_category in self.taintTracker.taint_category_ret): 
            normalizedEIPNames = self.taintTracker.x86ISA.getNormalizedX86RegisterNames("eip", 4,instRec.currentThreadId)
            for normalizedEIP in normalizedEIPNames:
                eipName = normalizedEIP
                if(eipName in self.taintTracker.dynamic_taint):
                    if self.bDebug==1:
                        print ("tainted = %s" %self.taintTracker.dynamic_taint[eipName].taint_tree())
                    self.taintTracker.dynamic_taint[eipName].dumpTaintTree(self.taintTracker.output_fd)
                    #self.output_fd.write("%s\n" %self.dynamic_taint[eipName].taint_tree())
                    bTaint =1

            normalizedEBPNames = self.taintTracker.x86ISA.getNormalizedX86RegisterNames("ebp", 4,instRec.currentThreadId)
            for normalizedEBP in normalizedEIPNames:
                ebpName = normalizedEBP
                if(ebpName in self.taintTracker.dynamic_taint):
                    if self.bDebug==1:
                        print ("tainted = %s" %self.taintTracker.dynamic_taint[ebpName].taint_tree())
                        #self.output_fd.write("%s\n" %self.dynamic_taint[ebpName].taint_tree())
                    self.taintTracker.dynamic_taint[ebpName].dumpTaintTree(self.taintTracker.output_fd)
                    bTaint =1

            normalizedESPNames = self.taintTracker.x86ISA.getNormalizedX86RegisterNames("esp", 4,instRec.currentThreadId)
            for normalizedESP in normalizedESPNames:
                espName = normalizedESP
                if(espName in self.taintTracker.dynamic_taint):
                    if self.bDebug==1:
                        print ("tainted = %s" %self.taintTracker.dynamic_taint[espName].taint_tree())
                        #self.output_fd.write("%s\n" %self.dynamic_taint[espName].taint_tree())
                    self.taintTracker.dynamic_taint[espName].dumpTaintTree(self.taintTracker.output_fd)
                    bTaint=1					
        elif (instInfo.inst_category in self.taintTracker.taint_category_call): #check its register set 
            for reg in instRec.reg_value: 
                normalizedRegNames = self.taintTracker.x86ISA.getNormalizedX86RegisterNames(reg, 4,instRec.currentThreadId)
                for normalizedRegName in normalizedRegNames:
                    regName = normalizedRegName
                    if(regName in self.taintTracker.dynamic_taint):
                        if self.bDebug==1:
                            print ("tainted = %s" %self.taintTracker.dynamic_taint[regName].taint_tree())
                        self.taintTracker.dynamic_taint[regName].dumpTaintTree(self.taintTracker.output_fd)
                        bTaint =1
                #Check if the memory pointed by the reg is tainted
                memBase = instRec.reg_value[reg]
                for i in range(4):
                    if(memBase+i in self.taintTracker.dynamic_taint):
                        if self.bDebug==1:
                            print ("tainted = %s" %self.taintTracker.dynamic_taint[memBase+i].taint_tree())
                        self.taintTracker.dynamic_taint[memBase+i].dumpTaintTree(self.taintTracker.output_fd)
                        bTaint =1
        
        return bTaint

    def DumpFaultCause(self, tRecord, tLastERecord,verBose):

        faultAddress = tRecord.currentExceptionAddress
        self.taintTracker.output_fd.write("EXCEPTION:\n")
        strTaint ="EXCEPTION:\n"

        if(not(tLastERecord.currentInstruction in self.taintTracker.static_taint)):                
            instlen = tLastERecord.currentInstSize
            instcode = c_byte*instlen
            instBytes = instcode()
            if(self.taintTracker.trace_type ==IDA):
                for i in range(instlen):
                    sBytes = tLastERecord.sEncoding[2*i:(2*i+2)]
                    instBytes[i]= int(sBytes,16)
            elif(self.taintTracker.trace_type ==PIN):
                for i in range(instlen):
                    instBytes[i]= tLastERecord.sEncoding[i]
                        
            instInfo = instDecode()            
            result = self.taintTracker.xDecoder.decode_inst(instlen, pointer(instBytes),ctypes.byref((instInfo)))
            if result !=0:
                self.taintTracker.static_taint[tLastERecord.currentInstruction] = instInfo
            else:
                sDbg = "instruction %s not supported" %(tLastERecord.currentInstruction)
                log.debug(sDbg)
        else:
            instInfo = self.taintTracker.static_taint[tLastERecord.currentInstruction]

        sException= "Instruction=0x%x, %s, Thread=%x, Seq=0x%x\n" %(tLastERecord.currentInstruction,instInfo.attDisa,tLastERecord.currentThreadId,tLastERecord.currentInstSeq)
        if (self.bDebug==True):
            print ("%s" %sException)
            instInfo.printInfo()		
        self.taintTracker.output_fd.write("%s" %(sException))
        strTaint = strTaint + "%s" %(sException)
	
        for reg in tLastERecord.reg_value:
            if (self.bDebug==True):
                print ("reg= %s, value=%s" %(reg,tLastERecord.reg_value[reg]))
            #if(faultAddress == tLastERecord.reg_value[reg]):
            normalizedRegNames = self.taintTracker.x86ISA.getNormalizedX86RegisterNames(reg, 4,tLastERecord.currentThreadId)
            for normalizedRegName in normalizedRegNames:
                if (self.bDebug==True):
                    print ("Fault instruction: regName= %s" %normalizedRegName)
                if(normalizedRegName in self.taintTracker.dynamic_taint):
                    if (self.bDebug==True):
                        print ("tainted = %s" %self.taintTracker.dynamic_taint[normalizedRegName].taint_simple())
                    strTaint = strTaint + self.taintTracker.dynamic_taint[normalizedRegName].dumpTaintTree(self.taintTracker.output_fd)
                    
	    #Check if the memory pointed by the reg is tainted
            memBase = tLastERecord.reg_value[reg]
            if (tLastERecord.reg_value[reg]==faultAddress):
                for i in range(4):
                    if(memBase+i in self.taintTracker.dynamic_taint):
                        strTaint = strTaint + self.taintTracker.dynamic_taint[faultAddress+i].dumpTaintTree(self.taintTracker.output_fd)
                        if (self.bDebug==True):
                            print ("tainted = %s" %self.taintTracker.dynamic_taint[faultAddress+i].taint_simple())
        return strTaint
    
    def DumpExceptionAnalysis(self, tRecord, tLastERecord,verBose):
        faultAddress = tRecord.currentExceptionAddress
        
        self.taintTracker.Propagator(tLastERecord)
        
        if(not(tLastERecord.currentInstruction in self.taintTracker.static_taint)):                
            instlen = tLastERecord.currentInstSize
            instcode = c_byte*instlen
            instBytes = instcode()
            if(self.trace_type ==IDA):
                for i in range(instlen):
                    sBytes = tLastERecord.sEncoding[2*i:(2*i+2)]
                    instBytes[i]= int(sBytes,16)
            elif(self.trace_type ==PIN):
                for i in range(instlen):
                    instBytes[i]= tLastERecord.sEncoding[i]
                        
            instInfo = instDecode()            
            result = self.taintTracker.xDecoder.decode_inst(instlen, pointer(instBytes),ctypes.byref((instInfo)))
            if result !=0:
                self.taintTracker.static_taint[tLastERecord.currentInstruction] = instInfo
            else:
                sDbg = "instruction %s not supported" %(tLastERecord.currentInstruction)
                log.debug(sDbg)
        else:
            instInfo = self.taintTracker.static_taint[tLastERecord.currentInstruction]

        self.taintTracker.output_fd.write("EXCEPTION:\n")
        strTaint = "EXCEPTION:\n"
        sException= "Exception Instruction=0x%x, %s, Thread=%x, Seq=0x%x\n" %(tLastERecord.currentInstruction,instInfo.attDisa,tLastERecord.currentThreadId,tLastERecord.currentInstSeq)
        if (self.bDebug==True):
            print ("%s" %sException)
            instInfo.printInfo()		
        self.taintTracker.output_fd.write("%s" %(sException))
        strTaint = strTaint + "%s" %(sException)
        for i in range(instInfo.n_src_operand):
            if(instInfo.src_operands[i]._type == REGISTER):
                reg = instInfo.src_operands[i]._ea
                print ("src reg= %s" %(reg))
                if(reg.find("stackpop")!=-1):
                    reg = "ebp"
                normalizedRegNames = self.taintTracker.x86ISA.getNormalizedX86RegisterNames(reg, 4,tLastERecord.currentThreadId)
                for normalizedRegName in normalizedRegNames:
                    if (self.bDebug==True):
                        print ("Fault instruction: regName= %s" %normalizedRegName)
                    if(normalizedRegName in self.taintTracker.dynamic_taint):
                        if (self.bDebug==True):
                            print ("tainted = %s" %self.taintTracker.dynamic_taint[normalizedRegName].taint_simple())
                        strTaint = strTaint +self.taintTracker.dynamic_taint[normalizedRegName].dumpTaintTree(self.taintTracker.output_fd)

        for i in range(instInfo.n_dest_operand):
            if(instInfo.dest_operands[i]._type == REGISTER):
                reg = instInfo.dest_operands[i]._ea
                print ("dest reg= %s" %(reg))
                normalizedRegNames = self.taintTracker.x86ISA.getNormalizedX86RegisterNames(reg, 4,tLastERecord.currentThreadId)
                for normalizedRegName in normalizedRegNames:
                    if (self.bDebug==True):
                        print ("Fault instruction: regName= %s" %normalizedRegName)
                    if(normalizedRegName in self.taintTracker.dynamic_taint):
                        if (self.bDebug==True):
                            print ("tainted = %s" %self.taintTracker.dynamic_taint[normalizedRegName].taint_simple())
                        strTaint = strTaint +self.taintTracker.dynamic_taint[normalizedRegName].dumpTaintTree(self.taintTracker.output_fd)
            
        for reg in tLastERecord.reg_value:
            if (self.bDebug==True):
                print ("reg= %s, value=%s" %(reg,tLastERecord.reg_value[reg]))
            #if(faultAddress == tLastERecord.reg_value[reg]):
            normalizedRegNames = self.taintTracker.x86ISA.getNormalizedX86RegisterNames(reg, 4,tLastERecord.currentThreadId)
            for normalizedRegName in normalizedRegNames:
                if (self.bDebug==True):
                    print ("Fault instruction: regName= %s" %normalizedRegName)
                if(normalizedRegName in self.taintTracker.dynamic_taint):
                    if (self.bDebug==True):
                        print ("tainted = %s" %self.taintTracker.dynamic_taint[normalizedRegName].taint_simple())
                    strTaint = strTaint + self.taintTracker.dynamic_taint[normalizedRegName].dumpTaintTree(self.taintTracker.output_fd)
                    
	    #Check if the memory pointed by the reg is tainted
            memBase = tLastERecord.reg_value[reg]
            if (tLastERecord.reg_value[reg]==faultAddress):
                for i in range(4):
                    if(memBase+i in self.taintTracker.dynamic_taint):
                        strTaint = strTaint + self.taintTracker.dynamic_taint[faultAddress+i].dumpTaintTree(self.taintTracker.output_fd)
                        if (self.bDebug==True):
                            print ("tainted = %s" %self.taintTracker.dynamic_taint[faultAddress+i].taint_simple())
	return strTaint
    
        #DEBUG
        #self.DumpLiveTaints()

    def DumpLiveTaintsInOrder(self):
        self.taintTracker.output_fd.write("Live Taints in the order of creation:\n")
        
        for t in self.taintTracker.dynamic_taint:
            self.taintTracker.dynamic_taint[t].terminateTaint(-1,-1)
        
        for v in sorted(self.taintTracker.dynamic_taint.values() ):
            for key in self.taintTracker.dynamic_taint:
                if self.taintTracker.dynamic_taint[ key ] == v:
                    self.taintTracker.output_fd.write("%s \n" %(v.taint_tree()))
                    break

    def DumpLiveTaints(self):
        self.taintTracker.output_fd.write("Live Taints:\n")
        
        for t in self.taintTracker.dynamic_taint:
            self.taintTracker.dynamic_taint[t].terminateTaint(-1,-1)
        for t in self.taintTracker.dynamic_taint:
            newTaint = strTaint + "%s \n" %(self.taintTracker.dynamic_taint[t].taint_tree())	    
            strTaint = strTaint + newTaint
	    self.taintTracker.output_fd.write("%s \n" %(newTaint))
            #self.output_fd.write("%s \n" %(self.dynamic_taint[t].taint_simple()))
	return strTaint

    def DisplayPCs(self):
        self.taintTracker.output_fd.write("Path Conditions:\n")
                
        for t in self.taintTracker.pcs:
            self.taintTracker.output_fd.write("%s \n" %(t.taint_tree()))
