'''

This is the main class for CBASS(x86) taint propogation. 
   
 * @author Nathan Li
 * 
 */
'''
import logging
import struct
    
from CIDParser import InstructionTraceRecord
from ctypes.util import *
from ctypes import *
import ctypes

from x86Decoder import x86Decoder, instDecode, IMMEDIATE, REGISTER,INDIRECT
from CIDTaint import Taint, REGISTER_TAINT, MEMORY_TAINT, BRANCH_TAINT
import operator

log = logging.getLogger('CIDATA')

IDA = 0
PIN = 1

traceType = IDA

#X86 instruction category enumeration. Each category has same/similar semantics or some other common characteristics

X86_INVALID=0
X86_ThreeDNOW=1
X86_AES=2
X86_AVX=3
X86_BINARY=4
X86_BITBYTE=5
X86_BROADCAST=6
X86_CALL=7
X86_CMOV=8
X86_COND_BR=9
X86_CONVERT=10
X86_DATAXFER=11
X86_DECIMAL=12
X86_FCMOV=13
X86_FLAGOP=14
X86_INTERRUPT=15
X86_IO=16
X86_IOSTRINGOP=17
X86_LOGICAL=18
X86_MISC=19
X86_MMX=20
X86_NOP=21 
X86_PCLMULQDQ=22
X86_POP=23
X86_PREFETCH=24
X86_PUSH=25
X86_RET=26
X86_ROTATE=27
X86_SEGOP=28
X86_SEMAPHORE=29
X86_SHIFT=30
X86_SSE=31
X86_STRINGOP=32
X86_STTNI=33
X86_SYSCALL=34
X86_SYSRET=35
X86_SYSTEM=36
X86_UNCOND_BR=37
X86_VTX=38
X86_WIDENOP=39
X86_X87_ALU=40
X86_XSAVE=41
X86_XSAVEOPT=42
X86_LAST=43

#Taint propagation policy enumerations:
TAINT_NOPE =0 
TAINT_ADDRESS = 1
TAINT_BRANCH = 2
TAINT_COUNTER = 3
TAINT_DATA = 4
TAINT_LAST =  TAINT_DATA+1 #update when adding new policy

def getNormalizedX86EFlagName(tid):
    return "eflags"+"_"+str(tid)        
        
def getNormalizedX86RegisterNames(regname, width_bytes, tid):
    normalizedNames = []
    if (regname.lower() =="eax"):
        for i in range(int(width_bytes)):
            normalizedNames.append("eax_"+str(i)+"_"+str(tid))
    elif (regname.lower() =="al"):
        normalizedNames.append("eax_0"+"_"+str(tid))
    elif (regname.lower() =="ah"):
        normalizedNames.append("eax_1"+"_"+str(tid))
    elif (regname.lower() =="ax"):
        normalizedNames.append("eax_0"+"_"+str(tid))
        normalizedNames.append("eax_1"+"_"+str(tid))    
    elif (regname.lower() =="ebx"):
        for i in range(int(width_bytes)):
            normalizedNames.append("ebx_"+str(i)+"_"+str(tid))
    elif (regname.lower() =="bl"):
        normalizedNames.append("ebx_0"+"_"+str(tid))
    elif (regname.lower() =="bh"):
        normalizedNames.append("ebx_1"+"_"+str(tid))
    elif (regname.lower() =="bx"):
        normalizedNames.append("ebx_0"+"_"+str(tid))
        normalizedNames.append("ebx_1"+"_"+str(tid)) 
    elif (regname.lower() =="ecx"):
        for i in range(int(width_bytes)):
            normalizedNames.append("ecx_"+str(i)+"_"+str(tid))
    elif (regname.lower() =="cl"):
        normalizedNames.append("ecx_0"+"_"+str(tid))
    elif (regname.lower() =="ch"):
        normalizedNames.append("ecx_1"+"_"+str(tid))
    elif (regname.lower() =="cx"):
        normalizedNames.append("ecx_0"+"_"+str(tid))
        normalizedNames.append("ecx_1"+"_"+str(tid)) 
    elif (regname.lower() =="edx"):
        for i in range(int(width_bytes)):
            normalizedNames.append("edx_"+str(i)+"_"+str(tid))
    elif (regname.lower() =="dl"):
        normalizedNames.append("edx_0"+"_"+str(tid))
    elif (regname.lower() =="dh"):
        normalizedNames.append("edx_1"+"_"+str(tid))
    elif (regname.lower() =="dx"):
        normalizedNames.append("edx_0"+"_"+str(tid))
        normalizedNames.append("edx_1"+"_"+str(tid)) 
    elif (regname.lower() =="bp"):
        normalizedNames.append("ebp_0"+"_"+str(tid))
        normalizedNames.append("ebp_1"+"_"+str(tid)) 
    else:
        sDbg ="getNormalizedX86RegisterNames: regName = %s" %str(regname.lower())
        log.debug(sDbg)
        
        for i in range(int(width_bytes)):
            normalizedNames.append(str(regname.lower())+"_"+str(i)+"_"+str(tid))
    '''
    elif (regname.lower() =="stackpop" or (regname.lower() =="stackpush")):
        normalizedNames.append("esp_0"+"_"+str(tid))
        normalizedNames.append("esp_1"+"_"+str(tid))
        normalizedNames.append("esp_2"+"_"+str(tid))
        normalizedNames.append("esp_3"+"_"+str(tid))
    '''
 
    return normalizedNames

class TaintPropagator(object):
    
    def __init__(self, processBits, targetBits, out_fd, taint_policy):
        self.xDecoder = x86Decoder(processBits, targetBits)
        self.targetBits = targetBits
        self.static_taint = {} #keyed by instruction encoding, and mapping to a static taint template
        self.dynamic_taint={} #keyed by memory or register/thread address, and mapping to its taint object(defined in CIDTaint) 
        self.output_fd = out_fd
        self.bDebug = False 
        self.taint_policy = taint_policy # TAINT_DATA is  DEFAULT
        
        self.category_name={}
        self.category_name[X86_INVALID]="Invalid"
        self.category_name[X86_ThreeDNOW]="ThreeDNOW"
        self.category_name[X86_AES]="AES"
        self.category_name[X86_AVX]="AVX"
        self.category_name[X86_BINARY]="Binary"
        self.category_name[X86_BITBYTE]="BitByte"
        self.category_name[X86_CALL]="Call"
        self.category_name[X86_CMOV]="CMov"
        self.category_name[X86_COND_BR]="Cond_BR"
        self.category_name[X86_DATAXFER]="DataXFER"
        self.category_name[X86_DECIMAL]="Decimal"
        self.category_name[X86_CONVERT]="Convert"
        self.category_name[X86_FCMOV]="FCMov"
        self.category_name[X86_FLAGOP]="FlagOP"
        self.category_name[X86_INTERRUPT]="Interrupt"
        self.category_name[X86_IO]="IO"
        self.category_name[X86_IOSTRINGOP]="IOStringOP"
        self.category_name[X86_LOGICAL]="Logical"
        self.category_name[X86_MISC]="Misc"
        self.category_name[X86_MMX]="MMX"
        self.category_name[X86_NOP]="NOP"
        self.category_name[X86_PCLMULQDQ]="PCLMULQDQ"
        self.category_name[X86_POP]="POP"
        self.category_name[X86_PREFETCH]="PREFETCH"
        self.category_name[X86_PUSH]="PUSH"
        self.category_name[X86_RET]="RET"
        self.category_name[X86_ROTATE]="ROTATE"
        self.category_name[X86_SEGOP]="SEGOP"
        self.category_name[X86_SEMAPHORE]="Semaphore"
        self.category_name[X86_SHIFT]="Shift"
        self.category_name[X86_SSE]="SSE"
        self.category_name[X86_STRINGOP]="StringOP"
        self.category_name[X86_STTNI]="STTNI"
        self.category_name[X86_SYSCALL]="Syscall"
        self.category_name[X86_SYSRET]="SysRET"
        self.category_name[X86_SYSTEM]="SYSTEM"
        self.category_name[X86_UNCOND_BR]="Uncond_BR"
        self.category_name[X86_VTX]="VTX"
        self.category_name[X86_WIDENOP]="WidenOP"
        self.category_name[X86_X87_ALU]="X87_ALU"
        self.category_name[X86_XSAVE]="XSAVE"
        self.category_name[X86_LAST]="LAST"
        
        self.taint_category_1To1 ={X86_DATAXFER}
        self.taint_category_2To1 ={X86_BINARY}
        self.taint_category_stackpush ={X86_PUSH}
        self.taint_category_stackpop ={X86_POP}
        self.taint_category_stringop = {X86_STRINGOP}
        self.taint_category_call = {X86_CALL}
        self.taint_category_ret = {X86_RET}
        self.taint_category_sink = {X86_CALL,X86_RET}
        self.taint_category_branch = {X86_COND_BR}        
        
        # A few more not defined, should be very rare 
    def Propagator(self, instRec):
        bTaint =0
        if(not(instRec.sEncoding in self.static_taint)):                
            instlen = instRec.currentInstSize
            instcode = c_byte*instlen
            instBytes = instcode()
            for i in range(instlen):
                sBytes = instRec.sEncoding[2*i:(2*i+2)]
                instBytes[i]= int(sBytes,16)

            instInfo = instDecode()            
            result = self.xDecoder.decode_inst(instlen, pointer(instBytes),ctypes.byref((instInfo)))
            if result !=0:
                if self.bDebug:
                    print("Get static_taint template for instruction %s first time:" %(instRec.sEncoding))
                    sDbg = instInfo.printInfo();
                    log.debug(sDbg)
                    sDbg = "Category: %s" %(self.category_name[instInfo.inst_category])
                    log.debug(sDbg)
                self.static_taint[instRec.sEncoding] = instInfo
            else:
                sDbg = "instruction %s not supported" %(instRec.sEncoding)
                log.debug(sDbg)
        else:
            #print("static_taint template for %s has been cached:" %(instRec.sEncoding))
            instInfo = self.static_taint[instRec.sEncoding]

            if self.bDebug:
                instInfo.printInfo()
                sDbg ="Category: %s" %(self.category_name[instInfo.inst_category])
                log.debug(sDbg)
            
        #Propagate according to selected policies
        sDbg = "Taint Propagating Sequence(%x) for %s:" %(instRec.currentInstSeq, instInfo.attDisa)
        log.debug(sDbg)

        if traceType == IDA:
            if(str(instInfo.attDisa).find("fs:")!=-1):
                sDbg = "IDA Trace doesn't handle FS segment register"
                log.debug(sDbg)
                return -1
            
        if(instInfo.inst_category in self.taint_category_stackpush):
            self.TaintPropogateStackPush(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_stackpop):
            self.TaintPropogateStackPop(instInfo, instRec)
        # Test 1To1 policy first, expand more later
        elif(instInfo.inst_category in self.taint_category_1To1):
            self.TaintPropogateUnary(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_2To1):
            if (self.taint_policy == TAINT_BRANCH):
                self.TaintPropogatePathCondition(instInfo, instRec)            
            else:                
                self.TaintPropogateBinary(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_stringop):
            self.TaintPropogateString(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_ret):
            self.TaintPropogateRet(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_branch):
            if (self.taint_policy == TAINT_BRANCH):
                self.TaintPropogateBranch(instInfo, instRec)
        else:
            sWarn = "UNIMPLEMENTED for %s. Category=%s" %(instInfo.attDisa, self.category_name[instInfo.inst_category])
            log.warning(sWarn)

        #Refining
        #if(instInfo.inst_category in self.taint_category_sink):
        #return self.TaintCheckSink(instInfo, instRec)
        #else:
        return 0

    def TaintPropogateBranch(self, instInfo, instRec):
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        print "Taint propagating Branch!"
        sDbg = "Taint propagating Branch %s:\n" %(instStr)
        log.debug(sDbg)
        eFlagName = getNormalizedX86EFlagName(tid)
        if (eFlagName in self.dynamic_taint):
            sDbg = "Taint Branch Condition:%s\n" %(self.dynamic_taint[eFlagName])
            log.debug(sDbg)
            strBranch = "bc_"+str(instRec.currentInstSeq)
            taint = Taint(BRANCH_TAINT,instRec.currentInstSeq,instRec.currentInstSeq,tid,instStr)
            Taint.uid2Taint[taint.tuid]= taint
            srcTaint = self.dynamic_taint[eFlagName]
            taint.addTaintDSources(srcTaint)
            self.dynamic_taint[strBranch] = taint

    def TaintPropogatePathCondition(self, instInfo, instRec):
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        print "Taint propagating Path Condition!"
        sDbg = "Taint propagating Path Condition %s:\n" %(instStr)
        log.debug(sDbg)
        if (instStr.find("cmp")!=-1):
            sDbg = "Taint propagating cmp instruction: %s:\n" %(instStr)
            log.debug(sDbg)
            #log.debug(instInfo.printInfo())
            bSrcTainted = False
            for i in range(instInfo.n_src_operand):
                if(instInfo.src_operands[i]._type == REGISTER):
                    normalizedSrcRegNames = getNormalizedX86RegisterNames(str(instInfo.src_operands[i]._ea).strip("b'"), instInfo.src_operands[i]._width_bits/8,tid)
                    srcLen = len(normalizedSrcRegNames)
                    taint = None
                    for j in range(srcLen):
                        if (normalizedSrcRegNames[j] in self.dynamic_taint):
                            bSrcTainted = True
                            # tainted destinations are some of the eflags: just use eflags to simplify for now
                            normalizedEFlagName = getNormalizedX86EFlagName(tid)
                            if taint is None:
                                taint = Taint(REGISTER_TAINT,normalizedEFlagName,instRec.currentInstSeq,tid,instStr)
                            Taint.uid2Taint[taint.tuid]= taint
                            srcTaint = self.dynamic_taint[normalizedSrcRegNames[j]]
                            taint.addTaintDSources(srcTaint)
                            
                    if (taint is not None):
                        if(normalizedEFlagName in self.dynamic_taint):
                            self.dynamic_taint[normalizedEFlagName].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                            sDbg ="ERASE %s\n" %(self.dynamic_taint[normalizedEFlagName])
                            log.debug(sDbg)
                        self.dynamic_taint[normalizedEFlagName] = taint                            
                        sDbg ="\nCreated Branch Taint:%s\n" %(self.dynamic_taint[normalizedEFlagName])
                        log.debug(sDbg)
                elif (instInfo.src_operands[i]._type == INDIRECT):
                    nBytes = int(instInfo.src_operands[i]._width_bits/8)
                    srcAddress = instRec.currentReadAddr
                    # tainted destinations are some of the eflags: just use eflags to simplify for now
                    normalizedEFlagName = getNormalizedX86EFlagName(tid)
                    taint = None
                    for j in range(nBytes):
                        if(srcAddress+j in self.dynamic_taint):
                            bSrcTainted = True
                            if taint is None:
                                taint = Taint(REGISTER_TAINT,normalizedEFlagName,instRec.currentInstSeq,tid,instStr)
                            Taint.uid2Taint[taint.tuid]= taint
                            srcTaint = self.dynamic_taint[srcAddress+j]
                            taint.addTaintDSources(srcTaint)
                    if (taint is not None):
                        self.dynamic_taint[normalizedEFlagName] = taint                            
                        sDbg ="\nCreated Branch Taint:%s\n" %(self.dynamic_taint[normalizedEFlagName])
                        log.debug(sDbg)

                        self.dynamic_taint[normalizedEFlagName] = taint                            
                        sDbg ="\nCreated New Taint:%s\n" %(self.dynamic_taint[normalizedEFlagName])
                        log.debug(sDbg)
                        
            # When all Src is not tainted, then untaint eflags 
            normalizedEFlagName = getNormalizedX86EFlagName(tid)
            if(normalizedEFlagName in self.dynamic_taint and bSrcTainted==False): 
                sDbg = "UNTAINT %s\n" %(self.dynamic_taint[normalizedEFlagName])
                log.debug(sDbg)
                del self.dynamic_taint[normalizedEFlagName]                            
        
    def TaintCheckSink(self, instInfo, instRec):
        sDbg = "Taint Check Sink %s at seq = %d:\n" %(instInfo.attDisa, instRec.currentInstSeq)
        print ("%s" %sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        bTaint = 0
        
        if (instInfo.inst_category in self.taint_category_ret): 
            normalizedEIPNames = getNormalizedX86RegisterNames("eip", 4,instRec.currentThreadId)
            for normalizedEIP in normalizedEIPNames:
                eipName = normalizedEIP
                if(eipName in self.dynamic_taint):
                    if self.bDebug==1:
                        print ("tainted = %s" %self.dynamic_taint[eipName].taint_tree())
                    self.dynamic_taint[eipName].dumpTaintTree(self.output_fd)
                    #self.output_fd.write("%s\n" %self.dynamic_taint[eipName].taint_tree())
                    bTaint =1

            normalizedEBPNames = getNormalizedX86RegisterNames("ebp", 4,instRec.currentThreadId)
            for normalizedEBP in normalizedEIPNames:
                ebpName = normalizedEBP
                if(ebpName in self.dynamic_taint):
                    if self.bDebug==1:
                        print ("tainted = %s" %self.dynamic_taint[ebpName].taint_tree())
                        #self.output_fd.write("%s\n" %self.dynamic_taint[ebpName].taint_tree())
                    self.dynamic_taint[ebpName].dumpTaintTree(self.output_fd)
                    bTaint =1

            normalizedESPNames = getNormalizedX86RegisterNames("esp", 4,instRec.currentThreadId)
            for normalizedESP in normalizedESPNames:
                espName = normalizedESP
                if(espName in self.dynamic_taint):
                    if self.bDebug==1:
                        print ("tainted = %s" %self.dynamic_taint[espName].taint_tree())
                        #self.output_fd.write("%s\n" %self.dynamic_taint[espName].taint_tree())
                    self.dynamic_taint[espName].dumpTaintTree(self.output_fd)
                    bTaint=1
        '''					
        elif (instInfo.inst_category in self.taint_category_call): #check its register set 
            for reg in instRec.reg_value: 
                normalizedRegNames = getNormalizedX86RegisterNames(reg, 4,instRec.currentThreadId)
                for normalizedRegName in normalizedRegNames:
                    regName = normalizedRegName
                    if(regName in self.dynamic_taint):
                        if self.bDebug==1:
                            print ("tainted = %s" %self.dynamic_taint[regName].taint_tree())
                        self.dynamic_taint[regName].dumpTaintTree(self.output_fd)
                        bTaint =1
                #Check if the memory pointed by the reg is tainted
                memBase = instRec.reg_value[reg]
                for i in range(4):
                    if(memBase+i in self.dynamic_taint):
                        if self.bDebug==1:
                            print ("tainted = %s" %self.dynamic_taint[memBase+i].taint_tree())
                        self.dynamic_taint[memBase+i].dumpTaintTree(self.output_fd)
                        bTaint =1
        '''
        return bTaint

    '''
    src_operand_num=3:
    width=32, rw=7, type=3, ea_string=b'SEG=DS:BASE=ESI:'
    width=32, rw=4, type=2, ea_string=b'ECX'
    width=32, rw=2, type=2, ea_string=b'EFLAGS[df ]'
    dest_operand_num=1:
    width=32, rw=5, type=3, ea_string=b'SEG=ES:BASE=EDI:'
    
    or 
    DEBUG:CIDATA:Category: StringOP
    DEBUG:CIDATA:Taint propagating String b'rep stosdl  (%edi)':
    
    DEBUG:CIDATA:TextTraceReader: 
    line:E 0x4ecb488b 3 10324041 Reg( edi=0x73c3eb8 eax=0x0 ecx=0x22 eflags=0x246 ) W 4 73c3eb8 0_0_0_0 

    '''
    def TaintPropogateString(self, instInfo, instRec):
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        sDbg = "Taint propagating String %s:\n" %(instStr)
        log.debug(sDbg)
        
        for i in range(instInfo.n_dest_operand):
            if(instInfo.dest_operands[i]._type == REGISTER):
                sErr ="\nStringOP suppose to have memory operand, not register:\n"
                log.error(sErr)
            elif (instInfo.dest_operands[i]._type == INDIRECT):
                nBytes = int(instInfo.dest_operands[i]._width_bits/8)
                # esi, edi and ecx always?
                destAddress = instRec.reg_value["edi"]
                for j in range(nBytes):
                    taint =None
                    for k in range(instInfo.n_src_operand):
                        if(instInfo.src_operands[k]._type == REGISTER):
                            sDbg = "%s register operands %s:\n" %(instStr, instInfo.src_operands[k]._ea)
                            log.debug(sDbg)

                            #if(str(instInfo.src_operands[k]._ea).strip("b'").lower().startswith('eflags')):
                            #    continue                          
                            #track counter taint based on policy setting
                            if(self.taint_policy == TAINT_COUNTER):							
                                if(str(instInfo.src_operands[k]._ea).strip("b'").lower().startswith('ecx')): #loop counter: add later
                                    sDbg = "ECX REP Prefix StringOP Operands %s:\n" %(str(instInfo.src_operands[k]._ea).strip("b'").lower())
                                    log.debug(sDbg)  
                                    normalizedSrcRegNames = getNormalizedX86RegisterNames(str(instInfo.src_operands[k]._ea).strip("b'"), instInfo.src_operands[k]._width_bits/8,tid)
                                # for binary mode
                                    srcLen = len(normalizedSrcRegNames)
                                    for l in range(srcLen):
                                        if (normalizedSrcRegNames[l] in self.dynamic_taint):
                                            if(taint is None):
                                                taint = Taint(MEMORY_TAINT,destAddress+j, instRec.currentInstSeq,tid,instStr)
                                                Taint.uid2Taint[taint.tuid]= taint
                                                taint.addTaintCSources(self.dynamic_taint[normalizedSrcRegNames[l]])
                                            else:
                                                taint.addTaintCSources(self.dynamic_taint[normalizedSrcRegNames[l]])
                        elif(instInfo.src_operands[k]._type == INDIRECT):
                            # esi, edi and ecx always???
                            #srcAddress = instRec.currentReadAddr
                            srcAddress = instRec.reg_value["esi"]
                            nBytes = (int)(instInfo.src_operands[k]._width_bits/8)
                            if(srcAddress+j in self.dynamic_taint): # One to One mapping
                                if(taint is None):
                                    taint = Taint(MEMORY_TAINT,destAddress+j, instRec.currentInstSeq,tid,instStr)
                                    Taint.uid2Taint[taint.tuid]= taint
                                    taint.addTaintDSources(self.dynamic_taint[srcAddress+j])
                                else:
                                    taint.addTaintDSources(self.dynamic_taint[srcAddress+j])
                                                                            
                    if (destAddress+j in self.dynamic_taint):
                        sDbg ="\nTaintPropogateString: Taint Erased:%s\n" %(self.dynamic_taint[destAddress+j])
                        log.debug(sDbg)
                        self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                        del self.dynamic_taint[destAddress+j]
                    if(taint !=None):
                        self.dynamic_taint[destAddress+j] = taint
                        sDbg ="\nTaintPropogateString: Created New Taint:%s\n" %(self.dynamic_taint[destAddress+j])
                        log.debug(sDbg)

            else:
                continue

    #customized taint processing for stackpush
    def TaintPropogateStackPush(self, instInfo, instRec):
        sDbg = "Taint propagating StackPush %s:\n" %(instInfo.attDisa)
        log.debug(sDbg)
        if self.bDebug:
            print("%s" %sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        
        destAddress = instRec.currentWriteAddr
        
        if (instInfo.n_src_operand==1): # expect one register or immediate here
            if(instInfo.src_operands[0]._type == REGISTER):
                normalizedSrcRegNames = getNormalizedX86RegisterNames(str(instInfo.src_operands[0]._ea).strip("b'"), instInfo.src_operands[0]._width_bits/8,tid)
                srcLen = len(normalizedSrcRegNames)
                for j in range(srcLen):
                    if (normalizedSrcRegNames[j] in self.dynamic_taint):
                        # look for tainted destinations
                        sDbg ="\nShould Taint memory addressed by [esp]:\n"
                        log.debug(sDbg)
                        taint = Taint(MEMORY_TAINT,destAddress+j, instRec.currentInstSeq, tid,instStr)
                        Taint.uid2Taint[taint.tuid]= taint
                        srcTaint = self.dynamic_taint[normalizedSrcRegNames[j]]
                        taint.addTaintDSources(srcTaint)
                        if(destAddress+j in self.dynamic_taint):
                            self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                        self.dynamic_taint[destAddress+j] = taint
                        sDbg ="\nCreated New Taint:%s\n" %(self.dynamic_taint[destAddress+j])
                        log.debug(sDbg)

                    else: #UNTAINT if necessary
                        if(destAddress+j in self.dynamic_taint):
                            self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                            del self.dynamic_taint[destAddress+j]
            elif (instInfo.src_operands[0]._type == INDIRECT):
                sDbg ="\nERROR: Not expecting memory operand \n"
                log.debug(sDbg)
            elif (instInfo.src_operands[0]._type == IMMEDIATE):
                srcLen = int(instInfo.src_operands[0]._width_bits/8)
                for j in range(srcLen):
                    if(destAddress+j in self.dynamic_taint):
                        self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                        sDbg = "%s\n" %(self.dynamic_taint[destAddress+j])
                        log.debug(sDbg)
                        del self.dynamic_taint[destAddress+j]
        else:
            sDbg ="\nERROR: Not expecting more than one source operand \n"
            log.debug(sDbg)

   #customized taint processing for stackpop
    def TaintPropogateStackPop(self, instInfo, instRec):
        sDbg = "Taint propagating StackPop %s:\n" %(instInfo.attDisa)
        log.debug(sDbg)
        if self.bDebug:
            print("%s" %sDbg)

        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if self.bDebug:
            instInfo.printInfo()
        srcAddress = instRec.currentReadAddr
        
        if (instInfo.n_dest_operand==1): # expect one register here
            if(instInfo.dest_operands[0]._type == REGISTER):
                normalizedDestRegNames = getNormalizedX86RegisterNames(str(instInfo.dest_operands[0]._ea).strip("b'"), instInfo.dest_operands[0]._width_bits/8,tid)
                destLen = len(normalizedDestRegNames)
                for j in range(destLen):
                    if (srcAddress+j in self.dynamic_taint):
                        # look for tainted destinations
                        sDbg ="\nTainted Stack memory propagated to register:\n"
                        log.debug(sDbg)
                        taint = Taint(REGISTER_TAINT,normalizedDestRegNames[j], instRec.currentInstSeq, tid,instStr)
                        Taint.uid2Taint[taint.tuid]= taint
                        srcTaint = self.dynamic_taint[srcAddress+j]
                        taint.addTaintDSources(srcTaint)
                        if(normalizedDestRegNames[j] in self.dynamic_taint):
                            self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                        #else:
                        #    self.output_fd.write("NEW %s\n" %(taint))
                        self.dynamic_taint[normalizedDestRegNames[j]] = taint
                        sDbg ="\nCreated New Taint:%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                        log.debug(sDbg)

                    else: # UNTAINT if the destination is tainted
                        if(normalizedDestRegNames[j] in self.dynamic_taint):
                            self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                            sDbg ="%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                            log.debug(sDbg)
                            del self.dynamic_taint[normalizedDestRegNames[j]]
                        
            elif (instInfo.dest_operands[0]._type == INDIRECT):
                sDbg ="\nTaintPropogateStackPop ERROR: Not expecting memory operand \n"
                log.debug(sDbg)
            elif (instInfo.dest_operands[0]._type == IMMEDIATE):
                sDbg ="\nTaintPropogateStackPop ERROR: Not expecting immediate operand \n"
                log.debug(sDbg)
        else:
            sDbg ="\nERROR: Not expecting more than one source operand \n"
            log.debug(sDbg)

    #customized taint processing for RET
    def TaintPropogateRet(self, instInfo, instRec):
        sDbg = "Taint propagating Ret: %s\n" %(instInfo.attDisa)
        log.debug(sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if self.bDebug:
            print("Taint propagating RET: %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand))
            instInfo.printInfo()
            
        srcAddress = instRec.currentReadAddr
        if (instInfo.n_dest_operand==1): # expect one register (eip) here
            if(instInfo.dest_operands[0]._type == REGISTER):
                normalizedDestRegNames = getNormalizedX86RegisterNames(str(instInfo.dest_operands[0]._ea).strip("b'"), instInfo.dest_operands[0]._width_bits/8,tid)
                destLen = len(normalizedDestRegNames)
                for j in range(destLen):
                    if (srcAddress+j in self.dynamic_taint):
                        # look for tainted destinations
                        sDbg ="\nTainted Stack memory propagated to register:\n"
                        log.debug(sDbg)
                        taint = Taint(REGISTER_TAINT,normalizedDestRegNames[j], instRec.currentInstSeq, tid,instStr)
                        Taint.uid2Taint[taint.tuid]= taint
                        srcTaint = self.dynamic_taint[srcAddress+j]
                        taint.addTaintDSources(srcTaint)
                        if(normalizedDestRegNames[j] in self.dynamic_taint):
                            self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                        self.dynamic_taint[normalizedDestRegNames[j]] = taint
                        sDbg ="\nCreated New Taint:%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                        log.debug(sDbg)
                    else: # UNTAINT if the destination is tainted
                        if(normalizedDestRegNames[j] in self.dynamic_taint):
                            self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                            sDbg ="%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                            log.debug(sDbg)
                            del self.dynamic_taint[normalizedDestRegNames[j]]                      
            elif (instInfo.dest_operands[0]._type == INDIRECT):
                sDbg ="\nTaintPropogateStackPop ERROR: Not expecting memory operand \n"
                log.debug(sDbg)
            elif (instInfo.dest_operands[0]._type == IMMEDIATE):
                sDbg ="\nTaintPropogateStackPop ERROR: Not expecting immediate operand \n"
                log.debug(sDbg)
        else:
            sDbg ="\nERROR: Not expecting more than one source operand \n"
            log.debug(sDbg)
                     
        
    def TaintPropogateUnary(self, instInfo, instRec):
        sDbg = "Taint propagating unary: %s\n" %(instInfo.attDisa)
        log.debug(sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if(instInfo.n_src_operand!=1 or instInfo.n_dest_operand!=1):
            print("Taint propagating unary is NOT Unary!!! %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand))
        
        for i in range(instInfo.n_src_operand):
            if(instInfo.src_operands[i]._type == REGISTER):
                normalizedSrcRegNames = getNormalizedX86RegisterNames(str(instInfo.src_operands[i]._ea).strip("b'"), instInfo.src_operands[i]._width_bits/8,tid)
                srcLen = len(normalizedSrcRegNames)
                for j in range(srcLen):
                    if (normalizedSrcRegNames[j] in self.dynamic_taint):
                        # look for tainted destinations
                        sDbg ="\nTainted dest_operand_num=%d:\n" %(instInfo.n_dest_operand)
                        log.debug(sDbg)
                        for k in range(instInfo.n_dest_operand):
                            if(instInfo.dest_operands[k]._type == REGISTER):
                                if(str(instInfo.dest_operands[k]._ea).strip("b'").lower()== 'eflags'):
                                    continue
                                normalizedDestRegNames = getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
                                # for 1-To-1 mode
                                taint = Taint(REGISTER_TAINT,normalizedDestRegNames[j], instRec.currentInstSeq,tid,instStr)
                                Taint.uid2Taint[taint.tuid]= taint
                                srcTaint = self.dynamic_taint[normalizedSrcRegNames[j]]
                                taint.addTaintDSources(srcTaint)                                
                                if(normalizedDestRegNames[j] in self.dynamic_taint):
                                    self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                                    sDbg ="ERASE %s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                                    log.debug(sDbg)
                                self.dynamic_taint[normalizedDestRegNames[j]] = taint                            
                                sDbg ="\nCreated New Taint:%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                                log.debug(sDbg)

                            elif(instInfo.dest_operands[k]._type == INDIRECT):
                                destAddress = instRec.currentWriteAddr
                                taint = Taint(MEMORY_TAINT,destAddress+j, instRec.currentInstSeq, tid,instStr)
                                Taint.uid2Taint[taint.tuid]= taint
                                srcTaint = self.dynamic_taint[normalizedSrcRegNames[j]]
                                taint.addTaintDSources(srcTaint)
                                if(destAddress+j in self.dynamic_taint):
                                    self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                                    #self.output_fd.write("%s\n" %(self.dynamic_taint[destAddress+j]))
                                self.dynamic_taint[destAddress+j] = taint
                                sDbg ="\nCreated New Taint:%s\n" %(self.dynamic_taint[destAddress+j])
                                log.debug(sDbg)

                    else: # Src is not tainted, then untaint is likely
                        for k in range(instInfo.n_dest_operand):
                            if(instInfo.dest_operands[k]._type == REGISTER):
                                if(str(instInfo.dest_operands[k]._ea).strip("b'").lower()== 'eflags'):
                                    continue
                                normalizedDestRegNames = getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
                                # for 1-To-1 mode
                                if(normalizedDestRegNames[j] in self.dynamic_taint): 
                                    sDbg = "UNTAINT %s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                                    log.debug(sDbg)
                                    del self.dynamic_taint[normalizedDestRegNames[j]]                            
                            elif(instInfo.dest_operands[k]._type == INDIRECT):
                                destAddress = instRec.currentWriteAddr
                                if(destAddress+j in self.dynamic_taint):
                                    self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                                    sDbg = "UNTAINT %s\n" %(self.dynamic_taint[destAddress+j])
                                    log.debug(sDbg)
                                    del self.dynamic_taint[destAddress+j]
                        
            elif (instInfo.src_operands[i]._type == INDIRECT):
                nBytes = int(instInfo.src_operands[i]._width_bits/8)
                srcAddress = instRec.currentReadAddr
                for j in range(nBytes):
                    if(srcAddress+j in self.dynamic_taint):
                        # taint all possible destinations 
                        sDbg ="\nTainted dest_operand_num=%d:\n" %(instInfo.n_dest_operand)
                        log.debug(sDbg)
                        for k in range(instInfo.n_dest_operand):
                            if(instInfo.dest_operands[k]._type == REGISTER):
                                if(str(instInfo.dest_operands[k]._ea).strip("b'").lower()== 'eflags'):
                                    continue
                                normalizedDestRegNames = getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
                                # for 1-To-1 mode
                                taint = Taint(REGISTER_TAINT,normalizedDestRegNames[j], instRec.currentInstSeq, tid,instStr)
                                Taint.uid2Taint[taint.tuid]= taint
                                srcTaint = self.dynamic_taint[srcAddress+j]
                                taint.addTaintDSources(srcTaint)
                                if(normalizedDestRegNames[j] in self.dynamic_taint): 
                                    self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                                    #self.output_fd.write("%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]]))
                                #else:
                                #    self.output_fd.write("NEW %s\n" %(taint))
                                self.dynamic_taint[normalizedDestRegNames[j]] = taint

                            elif(instInfo.dest_operands[k]._type == INDIRECT):
                                destAddress = instRec.currentWriteAddr
                                taint = Taint(MEMORY_TAINT,destAddress+j, instRec.currentInstSeq, tid,instStr)
                                Taint.uid2Taint[taint.tuid]= taint
                                srcTaint = self.dynamic_taint[srcAddress+j]
                                taint.addTaintDSources(srcTaint)
                                if(destAddress+j in self.dynamic_taint):
                                    self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                                    #self.output_fd.write("%s" %(self.dynamic_taint[destAddress+j]))
                                #else:
                                #    self.output_fd.write("NEW %s\n" %(taint))
                                self.dynamic_taint[destAddress+j] = taint
                                sDbg ="\nCreated New Taint:%s\n" %(self.dynamic_taint[destAddress+j])
                                log.debug(sDbg)
                                
                    else: # if src is not tainted, then untaint destination
                        for k in range(instInfo.n_dest_operand):
                            if(instInfo.dest_operands[k]._type == REGISTER):
                                if(str(instInfo.dest_operands[k]._ea).strip("b'").lower()== 'eflags'):
                                    continue
                                normalizedDestRegNames = getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
                                # for 1-To-1 mode
                                if(normalizedDestRegNames[j] in self.dynamic_taint): 
                                    self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                                    sDbg = "UnTAINT:%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                                    log.debug(sDbg)
                                    del self.dynamic_taint[normalizedDestRegNames[j]]

                            elif(instInfo.dest_operands[k]._type == INDIRECT):
                                destAddress = instRec.currentWriteAddr
                                if(destAddress+j in self.dynamic_taint):
                                    self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                                    sDbg = "UNTAINT %s" %(self.dynamic_taint[destAddress+j])
                                    log.debug(sDbg)
                                    del self.dynamic_taint[destAddress+j]
            else:
                continue
    def TaintPropogateCmp(self, instInfo, instRec):
        if self.bDebug:
            print("Ignore CMP flags for now")
        return
    
    def TaintPropogateBinary(self, instInfo, instRec):
        sDbg = "Taint propagating binary %s:\n" %(instInfo.attDisa)
        log.debug(sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if self.bDebug:
            print("Taint propagating binary: %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand))
        if(str(instInfo.attDisa).find("cmp")!=-1):
            return self.TaintPropogateCmp(instInfo, instRec)
            
        for i in range(instInfo.n_dest_operand):
            if(instInfo.dest_operands[i]._type == REGISTER):
                normalizedDestRegNames = getNormalizedX86RegisterNames(str(instInfo.dest_operands[i]._ea).strip("b'"), instInfo.dest_operands[i]._width_bits/8,tid)
                destLen = len(normalizedDestRegNames)
                for j in range(destLen):
                    taint =None
                    for k in range(instInfo.n_src_operand):
                        if(instInfo.src_operands[k]._type == REGISTER):
                            if(str(instInfo.dest_operands[k]._ea).strip("b'").lower()== 'eflags'):
                                continue
                            normalizedSrcRegNames = getNormalizedX86RegisterNames(str(instInfo.src_operands[k]._ea).strip("b'"), instInfo.src_operands[k]._width_bits/8,tid)
                            # for binary mode
                            srcLen = len(normalizedSrcRegNames)
                            for l in range(srcLen):
                                if (normalizedSrcRegNames[l] in self.dynamic_taint):
                                    if(taint is None):
                                        taint = Taint(REGISTER_TAINT,normalizedDestRegNames[j], instRec.currentInstSeq,tid,instStr)
                                        Taint.uid2Taint[taint.tuid]= taint
                                        taint.addTaintDSources(self.dynamic_taint[normalizedSrcRegNames[l]])
                                    else:
                                        taint.addTaintDSources(self.dynamic_taint[normalizedSrcRegNames[l]])                        
                        elif(instInfo.src_operands[k]._type == INDIRECT):
                            srcAddress = instRec.currentReadAddr
                            nBytes = (int)(instInfo.src_operands[k]._width_bits/8)
                            for l in range(nBytes):
                                if(srcAddress+l in self.dynamic_taint):
                                    sDbg ="TaintPropogateBinary: %x is Tainted\n" %(srcAddress+l)
                                    log.debug(sDbg)

                                    if(taint is None):
                                        taint = Taint(REGISTER_TAINT,normalizedDestRegNames[j], instRec.currentInstSeq,tid,instStr)
                                        Taint.uid2Taint[taint.tuid]= taint
                                        taint.addTaintDSources(self.dynamic_taint[srcAddress+l])
                                    else:
                                        taint.addTaintDSources(self.dynamic_taint[srcAddress+l])
                                                                            
                    if(taint !=None):
                        self.dynamic_taint[normalizedDestRegNames[j]] = taint
                        sDbg ="\nCreated New Taint for %s : %s\n" %(normalizedDestRegNames[j], self.dynamic_taint[normalizedDestRegNames[j]])
                        log.debug(sDbg)
                    elif (normalizedDestRegNames[j] in self.dynamic_taint):
                        sDbg ="\nTaint Erased:%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                        log.debug(sDbg)
                        self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)

            elif (instInfo.dest_operands[i]._type == INDIRECT):
                nBytes = int(instInfo.dest_operands[i]._width_bits/8)
                destAddress = instRec.currentWriteAddr
                for j in range(nBytes):
                    taint =None
                    for k in range(instInfo.n_src_operand):
                        if(instInfo.src_operands[k]._type == REGISTER):
                            if(str(instInfo.dest_operands[k]._ea).strip("b'").lower()== 'eflags'):
                                continue
                            normalizedSrcRegNames = getNormalizedX86RegisterNames(str(instInfo.src_operands[k]._ea).strip("b'"), instInfo.src_operands[k]._width_bits/8,tid)
                            # for binary mode
                            srcLen = len(normalizedSrcRegNames)
                            for l in range(srcLen):
                                if (normalizedSrcRegNames[l] in self.dynamic_taint):
                                    if(taint is None):
                                        taint = Taint(MEMORY_TAINT,destAddress+j, instRec.currentInstSeq,tid,instStr)
                                        Taint.uid2Taint[taint.tuid]= taint
                                        taint.addTaintDSources(self.dynamic_taint[normalizedSrcRegNames[l]])
                                    else:
                                        taint.addTaintDSources(self.dynamic_taint[normalizedSrcRegNames[l]])                        
                        elif(instInfo.src_operands[k]._type == INDIRECT):
                            srcAddress = instRec.currentReadAddr
                            nBytes = (int)(instInfo.src_operands[k]._width_bits/8)
                            for l in range(nBytes):
                                if(srcAddress+l in self.dynamic_taint):
                                    if(taint is None):
                                        taint = Taint(MEMORY_TAINT,destAddress+j, instRec.currentInstSeq,tid,instStr)
                                        Taint.uid2Taint[taint.tuid]= taint
                                        taint.addTaintDSources(self.dynamic_taint[srcAddress+l])
                                    else:
                                        taint.addTaintDSources(self.dynamic_taint[srcAddress+l])
                                                                                                    
                    if(taint !=None):
                        self.dynamic_taint[destAddress+j] = taint
                        sDbg ="\nCreated New Taint:%s\n" %(self.dynamic_taint[destAddress+j])
                        log.debug(sDbg)
                    elif (destAddress+j in self.dynamic_taint):
                        sDbg ="\nTaint Erased:%s\n" %(self.dynamic_taint[destAddress+j])
                        log.debug(sDbg)
                        self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
            else:
                continue
 
    def DumpFaultCause(self, tRecord, tLastERecord,verBose):

        faultAddress = tRecord.currentExceptionAddress
        
        self.output_fd.write("EXCEPTION:\n")
        if(not(tLastERecord.sEncoding in self.static_taint)):                
            instlen = tLastERecord.currentInstSize
            instcode = c_byte*instlen
            instBytes = instcode()
            for i in range(instlen):
                sBytes = tLastERecord.sEncoding[2*i:(2*i+2)]
                instBytes[i]= int(sBytes,16)

            instInfo = instDecode()            
            result = self.xDecoder.decode_inst(instlen, pointer(instBytes),ctypes.byref((instInfo)))
            if result !=0:
                self.static_taint[tLastERecord.sEncoding] = instInfo
            else:
                sDbg = "instruction %s not supported" %(tLastERecord.sEncoding)
                log.debug(sDbg)
        else:
            #print("static_taint template for %s has been cached:" %(instRec.sEncoding))
            instInfo = self.static_taint[tLastERecord.sEncoding]

        sException= "Instruction=0x%x, %s, Thread=%x, Seq=0x%x\n" %(tLastERecord.currentInstruction,instInfo.attDisa,tLastERecord.currentThreadId,tLastERecord.currentInstSeq)
        instInfo.printInfo()		
        self.output_fd.write("%s" %(sException))

        #DEBUG self.DumpLiveTaints()
        for reg in tLastERecord.reg_value:
            print ("reg= %s, value=%s" %(reg,tLastERecord.reg_value[reg]))
            if(faultAddress == tLastERecord.reg_value[reg]):
                normalizedRegNames = getNormalizedX86RegisterNames(reg, 4,tLastERecord.currentThreadId)
                for normalizedRegName in normalizedRegNames:
                    print ("Fault instruction: regName= %s" %normalizedRegName)
                    if(normalizedRegName in self.dynamic_taint):
                        print ("tainted = %s" %self.dynamic_taint[normalizedRegName].taint_simple())
                        self.dynamic_taint[normalizedRegName].dumpTaintTree(self.output_fd)

			#Check if the memory pointed by the reg is tainted
            memBase = tLastERecord.reg_value[reg]
            if (tLastERecord.reg_value[reg]==faultAddress):
                for i in range(4):
                    if(memBase+i in self.dynamic_taint):
                        self.dynamic_taint[faultAddress+i].dumpTaintTree(self.output_fd)
                        print ("tainted = %s" %self.dynamic_taint[faultAddress+i].taint_simple())
						
    def DumpLiveTaintsInOrder(self):
        self.output_fd.write("Live Taints in the order of creation:\n")
        
        for t in self.dynamic_taint:
            self.dynamic_taint[t].terminateTaint(-1,-1)
        
        for v in sorted(self.dynamic_taint.values() ):
            for key in self.dynamic_taint:
                if self.dynamic_taint[ key ] == v:
                    self.output_fd.write("%s \n" %(v.taint_tree()))
                    break

    def DumpLiveTaints(self):
        self.output_fd.write("Live Taints:\n")
        
        for t in self.dynamic_taint:
            self.dynamic_taint[t].terminateTaint(-1,-1)
        for t in self.dynamic_taint: 
            self.output_fd.write("%s \n" %(self.dynamic_taint[t].taint_tree()))
        
    def SetInputTaint(self, address, size):
        for i in range(size):
            taint = Taint(MEMORY_TAINT,address+i, -1, -1, "INPUT",True)
            Taint.uid2Taint[taint.tuid]= taint
            '''
            if(address+i in self.dynamic_taint): 
                self.output_fd.write("%s\n" %(self.dynamic_taint[address]))
            else:
                self.output_fd.write("INPUT: %s\n" %(taint))
            '''
            self.dynamic_taint[address+i] = taint
            
                    
