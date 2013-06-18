'''
    This is the main class for TREE taint tracking for x86 instruction set.
    
    TREE tracks taint through a combination of static taint template/category and instruction-specific propogation.
    The static taint template and category is generated using the x86Decoder (based on XED) we developed.
    x86 instructions are divided into categories by their semantics and TREE leverages their common characteristics to
    simplify general taint tracking. However, even instructions in the same category can have subtle differences that will affect
    the precision and correctness of taint propogation. So TREE handles such instructions case-by-case to reduce over-taint and under-taint problems.
    
    See design docoument for some design decisions
    For complete x86 instruction semantics, check out Intel Architecture Software Developer's Manual, particularly Volume 2" Instruction Set Reference
   
 * @author Nathan Li
 * 
 */
'''
import logging
import struct
from ctypes.util import *
from ctypes import *
import ctypes
import operator

from TraceParser import InstructionTraceRecord
from x86Decoder import x86Decoder, instDecode, IMMEDIATE, REGISTER,MEMORY, WINDOWS, LINUX
from Taint import Taint, INPUT_TAINT, REGISTER_TAINT, MEMORY_TAINT, BRANCH_TAINT
from x86ISA import X86ISA
from TaintChecker import TaintChecker

log = logging.getLogger('TREE')

#Trace type enumeration
IDA = 0
PIN = 1

#Taint propagation policy enumerations:
TAINT_NOPE =0 
TAINT_ADDRESS = 1
TAINT_BRANCH = 2
TAINT_COUNTER = 3
TAINT_DATA = 4
TAINT_LAST =  TAINT_DATA+1 #update when adding new policy

class TaintTracker(object):
    
    def __init__(self, hostOS, processBits, targetBits, out_fd, taint_policy,trace_type):
        self.x86ISA = X86ISA()
        self.TC = TaintChecker(self)
        self.xDecoder = x86Decoder(processBits, targetBits, hostOS)
        self.targetBits = targetBits
        self.static_taint = {} #keyed by instruction encoding, and mapping to a static taint template
        self.dynamic_taint={} #keyed by memory or register/thread address, and mapping to its taint object(defined in CIDTaint) 
        self.output_fd = out_fd
        self.bDebug = True
        self.taint_policy = taint_policy # TAINT_DATA is  DEFAULT
        self.trace_type = trace_type
        self.pcs =[]
        
        self.category_name={}
        self.category_name[X86ISA.X86_INVALID]="Invalid"
        self.category_name[X86ISA.X86_ThreeDNOW]="ThreeDNOW"
        self.category_name[X86ISA.X86_AES]="AES"
        self.category_name[X86ISA.X86_AVX]="AVX"
        self.category_name[X86ISA.X86_BINARY]="Binary"
        self.category_name[X86ISA.X86_BITBYTE]="BitByte"
        self.category_name[X86ISA.X86_CALL]="Call"
        self.category_name[X86ISA.X86_CMOV]="CMov"
        self.category_name[X86ISA.X86_COND_BR]="Cond_BR"
        self.category_name[X86ISA.X86_DATAXFER]="DataXFER"
        self.category_name[X86ISA.X86_DECIMAL]="Decimal"
        self.category_name[X86ISA.X86_CONVERT]="Convert"
        self.category_name[X86ISA.X86_FCMOV]="FCMov"
        self.category_name[X86ISA.X86_FLAGOP]="FlagOP"
        self.category_name[X86ISA.X86_INTERRUPT]="Interrupt"
        self.category_name[X86ISA.X86_IO]="IO"
        self.category_name[X86ISA.X86_IOSTRINGOP]="IOStringOP"
        self.category_name[X86ISA.X86_LOGICAL]="Logical"
        self.category_name[X86ISA.X86_MISC]="Misc"
        self.category_name[X86ISA.X86_MMX]="MMX"
        self.category_name[X86ISA.X86_NOP]="NOP"
        self.category_name[X86ISA.X86_PCLMULQDQ]="PCLMULQDQ"
        self.category_name[X86ISA.X86_POP]="POP"
        self.category_name[X86ISA.X86_PREFETCH]="PREFETCH"
        self.category_name[X86ISA.X86_PUSH]="PUSH"
        self.category_name[X86ISA.X86_RET]="RET"
        self.category_name[X86ISA.X86_ROTATE]="ROTATE"
        self.category_name[X86ISA.X86_SEGOP]="SEGOP"
        self.category_name[X86ISA.X86_SEMAPHORE]="Semaphore"
        self.category_name[X86ISA.X86_SHIFT]="Shift"
        self.category_name[X86ISA.X86_SSE]="SSE"
        self.category_name[X86ISA.X86_STRINGOP]="StringOP"
        self.category_name[X86ISA.X86_STTNI]="STTNI"
        self.category_name[X86ISA.X86_SYSCALL]="Syscall"
        self.category_name[X86ISA.X86_SYSRET]="SysRET"
        self.category_name[X86ISA.X86_SYSTEM]="SYSTEM"
        self.category_name[X86ISA.X86_UNCOND_BR]="Uncond_BR"
        self.category_name[X86ISA.X86_VTX]="VTX"
        self.category_name[X86ISA.X86_WIDENOP]="WidenOP"
        self.category_name[X86ISA.X86_X87_ALU]="X87_ALU"
        self.category_name[X86ISA.X86_XSAVE]="XSAVE"
        self.category_name[X86ISA.X86_LAST]="LAST"
        
        self.taint_category_1To1 ={X86ISA.X86_DATAXFER}
        self.taint_category_2To1 ={X86ISA.X86_BINARY}
        self.taint_category_stackpush ={X86ISA.X86_PUSH}
        self.taint_category_stackpop ={X86ISA.X86_POP}
        self.taint_category_stringop = {X86ISA.X86_STRINGOP}
        self.taint_category_call = {X86ISA.X86_CALL}
        self.taint_category_ret = {X86ISA.X86_RET}
        self.taint_category_sink = {X86ISA.X86_CALL,X86ISA.X86_RET}
        self.taint_category_branch = {X86ISA.X86_COND_BR}        
        self.taint_category_logic = {X86ISA.X86_LOGICAL}
        self.taint_category_shift = {X86ISA.X86_SHIFT}
        self.taint_category_eflags = {X86ISA.X86_FLAGOP,X86ISA.X86_BITBYTE}        
        self.taint_category_misc = {X86ISA.X86_MISC}
        self.taint_category_todo = {X86ISA.X86_MMX, X86ISA.X86_SEMAPHORE, X86ISA.X86_SYSCALL, X86ISA.X86_SYSRET, X86ISA.X86_SYSTEM}        
        self.taint_category_Ignore = {X86ISA.X86_INVALID, X86ISA.X86_UNCOND_BR,X86ISA.X86_ThreeDNOW,X86ISA.X86_VTX,X86ISA.X86_WIDENOP,X86ISA.X86_X87_ALU,X86ISA.X86_XSAVE} #categories that are not significant to TA
        if self.bDebug:
            print("Construct Taint Propogater")
        # A few more not defined, should be very rare
        
    def Propagator(self, instRec):
        bTaint =0
        if(not(instRec.currentInstruction in self.static_taint)):                
            instlen = instRec.currentInstSize
            instcode = c_byte*instlen
            instBytes = instcode()
            if(self.trace_type ==IDA):
                for i in range(instlen):
                    sBytes = instRec.sEncoding[2*i:(2*i+2)]
                    instBytes[i]= int(sBytes,16)
            elif (self.trace_type ==PIN):
                i=0 #PIN
                for byte in instRec.sEncoding:
                    instBytes[i]= byte
                    i=i+1
            
            instInfo = instDecode()            
            result = self.xDecoder.decode_inst(instlen, pointer(instBytes),ctypes.byref((instInfo)))
            if result !=0:
                if self.bDebug:
                    print("Get static_taint template for instruction %s first time:" %(instRec.currentInstruction))
                    #sDbg = instInfo.getDebugInfo();
                    #log.debug(sDbg)
                self.static_taint[instRec.currentInstruction] = instInfo
            else:
                sDbg = "instruction %s not supported" %(str(instRec.sEncoding))
                log.debug(sDbg)
        else:
            instInfo = self.static_taint[instRec.currentInstruction]

            if self.bDebug:
                sDbg = instInfo.getDebugInfo()
                log.debug(sDbg)
        
        #Propagate according to selected policies
        sDbg = "Beginning Taint Propagating Sequence(%x) for %s:" %(instRec.currentInstSeq, instInfo.attDisa)
        log.debug(sDbg)

        if self.bDebug:
            sDbg = instInfo.getDebugInfo();
            log.debug(sDbg)
            sDbg = instRec.getDebugInfo();
            log.debug(sDbg)

        if self.trace_type == IDA:
            if(str(instInfo.attDisa).find("fs:")!=-1):
                sDbg = "IDA Trace doesn't handle FS segment register"
                log.debug(sDbg)
                return -1

        if (instInfo.inst_category in self.taint_category_Ignore):
            sDbg = "End of Taint Propagating Sequence(%x) for %s \n" %(instRec.currentInstSeq, instInfo.attDisa)
            log.debug(sDbg)            
            return 0                
        elif(instInfo.inst_category in self.taint_category_stackpush):
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
        elif (instInfo.inst_category in self.taint_category_logic):
            self.TaintPropogateLogic(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_sink):
            return self.TC.TaintCheckTargets(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_misc):
            return self.TaintPropogateMisc(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_shift):
            return self.TaintPropogateShift(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_eflags):
            return self.TaintPropogateEflags(instInfo, instRec)
        elif (instInfo.inst_category in self.taint_category_todo):
            sWarn = "TODO:  %s. Category=%s" %(instInfo.attDisa, self.category_name[instInfo.inst_category])
            log.warning(sWarn)
        else:
            sWarn = "UNIMPLEMENTED for %s. Category=%s" %(instInfo.attDisa, self.category_name[instInfo.inst_category])
            log.warning(sWarn)

        sDbg = "End of Taint Propagating Sequence(%x) for %s \n" %(instRec.currentInstSeq, instInfo.attDisa)
        log.debug(sDbg)

        #Refining
        return 0

    '''
    LEAVE instruction releases the stack frame set up by an earlier ENTER instruction. The LEAVE
    instruction copies the frame pointer (in the EBP register) into the stack pointer register (ESP),
    which releases the stack space allocated to the stack frame. The old frame pointer (the frame
    pointer for the calling procedure that was saved by the ENTER instruction) is then popped from
    the stack into the EBP register, restoring the calling procedure's stack frame.
    
    Inst_category=19, Disassembly: leavel  
    src_operand_num=3:
    width=32, rw=2, type=3, ea_string=SEG=SS:BASE=EBP:
    width=32, rw=1, type=2, ea_string=EBP
    width=32, rw=1, type=2, ea_string=ESP
    dest_operand_num=2:
    width=32, rw=1, type=2, ea_string=EBP
    width=32, rw=1, type=2, ea_string=ESP
    
    Two effects:
    EBP-> ESP_new
    Mem[ESP_new] -> EBP
    
    '''
    def TaintPropogateLeave(self,instInfo, instRec):
        if self.bDebug:
            #print "Taint propagating LEAVE at Seq = 0x%x!" %(instRec.currentInstSeq)
            sDbg = instInfo.getDebugInfo()
            log.debug(sDbg)
            
        if(instInfo.n_src_operand!=3 or instInfo.n_dest_operand!=2):
            print("Taint propagating LEA expecting single source and destination operand!!! %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand))
            return
        
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        
        #     EBP-> ESP_new
        normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames("EBP", 4,tid)
        normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames("ESP", 4,tid)
        srcLen = 4
        for j in range(srcLen):
            if (normalizedSrcRegNames[j] in self.dynamic_taint):
                if self.bDebug:
                    log.debug("Taint propagating LEAVE: EBP Tainted!")
                # look for tainted destinations
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
            else: #EBP[j] is not tainted
                if self.bDebug:
                    print("Taint propagating LEAVE: EBP NOT Tainted!")
                if(normalizedDestRegNames[j] in self.dynamic_taint): #Detaint
                    self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                    del self.dynamic_taint[normalizedDestRegNames[j]]
        
        # pop memory from (new)stack top to EBP
        srcAddress = None
        srcAddress = instRec.reg_value["ebp"]
        if(srcAddress ==None):
            print("Bad EBP Value")
            return
        
        normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames("EBP", 4,tid)
        srcLen = 4
        for j in range(srcLen):
            if ((srcAddress+j in self.dynamic_taint)):
                if self.bDebug:
                    print("Taint propagating LEAVE: EBP Will Be Tainted!")
                # look for tainted destinations
                # for 1-To-1 mode
                taint = Taint(REGISTER_TAINT,normalizedDestRegNames[j], instRec.currentInstSeq,tid,instStr)
                Taint.uid2Taint[taint.tuid]= taint
                srcTaint = self.dynamic_taint[srcAddress+j]
                taint.addTaintDSources(srcTaint)                                
                if(normalizedDestRegNames[j] in self.dynamic_taint):
                    self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                    sDbg ="LEAVE ERASE %s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                    log.debug(sDbg)
                self.dynamic_taint[normalizedDestRegNames[j]] = taint                            
                sDbg ="\n LEAVE Created New Taint:%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                log.debug(sDbg)
            else: #meme[srcAddress+j] is not tainted
                if self.bDebug:
                    print("Taint propagating LEAVE: EBP Will NOT Be Tainted!")
                if(normalizedDestRegNames[j] in self.dynamic_taint): #Detaint
                    self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                    del self.dynamic_taint[normalizedDestRegNames[j]]

    '''
    LEA-Load Effective Address
    Computs the effective address(EA) from the source operand and stores it in the destination operand
    Note: the EA address is only computed, not accessed
    
    Example:
        Inst_category=19, Disassembly: lea 0x10(%esp), %ebp
        src_operand_num=1:
        width=32, rw=2, type=3, ea_string=BASE=ESP:DISP=16
        dest_operand_num=1:
        width=32, rw=3, type=2, ea_string=EBP
    
    '''
    def GetEAValue(self, strEA,instRec):
        EAValue = 0
        baseValue= 0
        indexValue= 0
        scaleValue= 0
        offset =0
        #Parse strEA into the parts of SEG:BASE:SCALE:INDEX:DISPLACEMENT
        EAParts = strEA.strip().split(":")
        for i in range(len(EAParts)):
            #print ("%s" %(EAParts[i]))
            equation = EAParts[i].split("=")
            if(len(equation)>1):
                #if self.bDebug:
                    #print ("LH = %s, RH = %s" %(equation[0], equation[1]))
                lh = equation[0]
                rh = equation[1]
                if(lh.find("SEG")!=-1):
                    if((rh.find("FS")!=-1) or (rh.find("SS")!=-1)):
                        sWarn = "TODO: handle FS or SS" 
                        log.warning(sWarn)
                    continue
                if(lh.find("BASE")!=-1):
                    baseValue = instRec.reg_value[rh.lower()]
                elif (lh.find("INDEX")!=-1):
                    indexValue = instRec.reg_value[rh.lower()]
                elif (lh.find("SCALE")!=-1):
                    scaleValue = int(rh)
                elif (lh.find("DISP")!=-1):
                    offset = int(rh)
                else:
                    print("Wrong Effective Address!")
                    return 0

        EAValue = baseValue + indexValue*scaleValue + offset                 
        return EAValue
    
    def TaintPropogateLea(self,instInfo, instRec):
        if self.bDebug:
            sDbg = instInfo.getDebugInfo()
            log.debug(sDbg)
        if(instInfo.n_src_operand!=1 or instInfo.n_dest_operand!=1):
            sErr = "Taint propagating LEA expecting single source and destination operand!!! %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand)
            log.error(sErr)
            return
        
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        SrcBaseReg = None
        SrcIndexReg = None
        
        #self.GetEAValue(instInfo.src_operands[0]._ea,instRec) # for debugging
        EAParts = instInfo.src_operands[0]._ea.strip().split(":")
        for i in range(len(EAParts)):
            equation = EAParts[i].split("=")
            if(len(equation)>1):
                lh = equation[0]
                rh = equation[1]
                if(lh.find("SEG")!=-1):
                    continue
                if(lh.find("BASE")!=-1):
                    SrcBaseReg = rh.lower()
                elif (lh.find("INDEX")!=-1):
                    SrcIndexReg = rh.lower()
                elif (lh.find("SCALE")!=-1):
                    continue # SCALSE is constant
                elif (lh.find("DISP")!=-1):
                    continue # DISP is constant
                
        DestReg = instInfo.dest_operands[0]._ea.strip()
        if (instInfo.dest_operands[0]._type != REGISTER):
            sErr = "Taint propagating LEA expecting destination as register!!! "
            log.error(sErr)
            return
        
        SrcTaint= False
        if(SrcBaseReg !=None):
            normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(SrcBaseReg, instInfo.src_operands[0]._width_bits/8,tid)
            normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(DestReg, instInfo.dest_operands[0]._width_bits/8,tid)
            srcLen = len(normalizedSrcRegNames) #bytes in the register
            for j in range(srcLen):
                if (normalizedSrcRegNames[j] in self.dynamic_taint):
                    SrcTaint =True
                    if self.bDebug:
                        print("Taint propagating LEA: Base Src Tainted!")
                    # look for tainted destinations
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
            
        if(SrcIndexReg !=None):
            normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(SrcIndexReg, instInfo.src_operands[0]._width_bits/8,tid)
            normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(DestReg, instInfo.dest_operands[0]._width_bits/8,tid)
            srcLen = len(normalizedSrcRegNames) #bytes in the register
            for j in range(srcLen):
                if (normalizedSrcRegNames[j] in self.dynamic_taint):
                    if self.bDebug:
                        print("Taint propagating LEA: Index Src Tainted!")                    
                    SrcTaint =True
                    # look for tainted destinations
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
                    if self.bDebug:
                        print ("%s" %sDbg)

        if(SrcTaint == False): #untaint destination may be necessary
            if self.bDebug:
                print("Taint propagating LEA: NO Src Tainted!")                    
            normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(DestReg, instInfo.dest_operands[0]._width_bits/8,tid)
            destLen = len(normalizedDestRegNames) #bytes in the register
            for j in range(destLen):
                if (normalizedDestRegNames[j] in self.dynamic_taint):
                    #Need detaint
                    if self.bDebug:
                        log.debug("Taint propagating LEA: DETaint NEEDED!")                    
                    self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                    sDbg ="ERASE %s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                    log.debug(sDbg)
                    del self.dynamic_taint[normalizedDestRegNames[j]]
            
    
    def  TaintPropogateMisc(self,instInfo, instRec):
        instStr = str(instInfo.attDisa).strip("b'")

        if (str(instInfo.attDisa).find("leave")!=-1):
            self.TaintPropogateLeave(instInfo,instRec)
        elif (str(instInfo.attDisa).find("lea")!=-1):
            self.TaintPropogateLea(instInfo,instRec)
        else:
            sWarn = "UNIMPLEMENTED for %s. Category=%s" %(instInfo.attDisa, self.category_name[instInfo.inst_category])
            log.warning(sWarn)

        '''
        Inst_category=30, Disassembly: shl $0x3, %esi
        src_operand_num=2:
        width=32, rw=1, type=2, ea_string=ESI
        width=8, rw=2, type=1, ea_string=3
        dest_operand_num=2:
        width=32, rw=1, type=2, ea_string=ESI
        width=32, rw=5, type=2, ea_string=EFLAGS[of sf zf af pf cf ]
        
        or
        Inst_category=30, Disassembly: shr %cl, %eax
        src_operand_num=2:
        width=32, rw=1, type=2, ea_string=EAX
        width=8, rw=2, type=2, ea_string=CL
        dest_operand_num=2:
        width=32, rw=1, type=2, ea_string=EAX
        width=32, rw=5, type=2, ea_string=EFLAGS[of sf zf af pf cf ]        
        '''        
    def TaintPropogateShift(self,instInfo, instRec):
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if (self.bDebug==True):
            sDbg = instInfo.getDebugInfo()
            log.debug(sDbg)
        #Treat it as an instance of m->n taint
        self.TaintPropogateBinary(instInfo, instRec)

        '''
        setz %al
        src_operand_num=1:
        width=32, rw=2, type=2, ea_string=EFLAGS[zf ]
        dest_operand_num=1:
        width=8, rw=3, type=2, ea_string=AL
        '''
        
        '''
        SETcc - Set Byte to 0 or 1 depending on Condition(eflag)in
        the EFLAGS register
        '''
    def TaintPropogateEflags(self,instInfo, instRec):
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if (self.bDebug==True):
            sDbg = instInfo.getDebugInfo()
            log.debug(sDbg)
        
    def TaintPropogateBranch(self, instInfo, instRec):
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if (self.bDebug==True):
            sDbg = instInfo.getDebugInfo()
            log.debug(sDbg)
        eFlagName = X86ISA.getNormalizedX86EFlagName(tid)
        if (eFlagName in self.dynamic_taint):
            sDbg = "Taint Branch Condition:%s\n" %(self.dynamic_taint[eFlagName])
            log.debug(sDbg)
            strBranch = "bc_"+str(instRec.currentInstSeq)
            taint = Taint(BRANCH_TAINT,instRec.currentInstSeq,instRec.currentInstSeq,tid,instStr)
            Taint.uid2Taint[taint.tuid]= taint
            srcTaint = self.dynamic_taint[eFlagName]
            taint.addTaintDSources(srcTaint)
            self.dynamic_taint[strBranch] = taint
            self.pcs.append(taint)

    def TaintPropogatePathCondition(self, instInfo, instRec):
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if (self.bDebug==True):
            sDbg = instInfo.getDebugInfo()
            sDbg = sDbg + "Taint propagating Path Condition %s:\n" %(instStr)
            log.debug(sDbg)
        if (instStr.find("cmp")!=-1):
            sDbg = "Taint propagating cmp instruction: %s:\n" %(instStr)
            log.debug(sDbg)
            bSrcTainted = False
            for i in range(instInfo.n_src_operand):
                if(instInfo.src_operands[i]._type == REGISTER):
                    normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[i]._ea).strip("b'"), instInfo.src_operands[i]._width_bits/8,tid)
                    srcLen = len(normalizedSrcRegNames)
                    taint = None
                    for j in range(srcLen):
                        if (normalizedSrcRegNames[j] in self.dynamic_taint):
                            bSrcTainted = True
                            # tainted destinations are some of the eflags: just use eflags to simplify for now
                            normalizedEFlagName = self.x86ISA.getNormalizedX86EFlagName(tid)
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
                elif (instInfo.src_operands[i]._type == MEMORY):
                    nBytes = int(instInfo.src_operands[i]._width_bits/8)
                    srcAddress = instRec.currentReadAddr
                    # tainted destinations are some of the eflags: just use eflags to simplify for now
                    normalizedEFlagName = self.x86ISA.getNormalizedX86EFlagName(tid)
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
            normalizedEFlagName = self.x86ISA.getNormalizedX86EFlagName(tid)
            if(normalizedEFlagName in self.dynamic_taint and bSrcTainted==False): 
                sDbg = "UNTAINT %s\n" %(self.dynamic_taint[normalizedEFlagName])
                log.debug(sDbg)
                del self.dynamic_taint[normalizedEFlagName]                            
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
        if self.bDebug:
            print("%s" %sDbg)
            
        for i in range(instInfo.n_dest_operand):
            if(instInfo.dest_operands[i]._type == REGISTER):
                sErr ="\nStringOP suppose to have memory operand, not register:\n"
                log.error(sErr)
            elif (instInfo.dest_operands[i]._type == MEMORY):
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
                                    normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[k]._ea).strip("b'"), instInfo.src_operands[k]._width_bits/8,tid)
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
                        elif(instInfo.src_operands[k]._type == MEMORY):
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
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        
        destAddress = instRec.currentWriteAddr
        
        if (instInfo.n_src_operand==1): # expect one register or immediate here
            if(instInfo.src_operands[0]._type == REGISTER):
                normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[0]._ea).strip("b'"), instInfo.src_operands[0]._width_bits/8,tid)
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
            elif (instInfo.src_operands[0]._type == MEMORY):
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
        #if self.bDebug:
        #    instInfo.printInfo()
        srcAddress = instRec.currentReadAddr
        
        if (instInfo.n_dest_operand==1): # expect one register here
            if(instInfo.dest_operands[0]._type == REGISTER):
                normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.dest_operands[0]._ea).strip("b'"), instInfo.dest_operands[0]._width_bits/8,tid)
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
                        
            elif (instInfo.dest_operands[0]._type == MEMORY):
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
            #instInfo.printInfo()
            
        srcAddress = instRec.currentReadAddr
        if (instInfo.n_dest_operand==1): # expect one register (eip) here
            if(instInfo.dest_operands[0]._type == REGISTER):
                normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.dest_operands[0]._ea).strip("b'"), instInfo.dest_operands[0]._width_bits/8,tid)
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
            elif (instInfo.dest_operands[0]._type == MEMORY):
                sDbg ="\nTaintPropogateStackPop ERROR: Not expecting memory operand \n"
                log.debug(sDbg)
            elif (instInfo.dest_operands[0]._type == IMMEDIATE):
                sDbg ="\nTaintPropogateStackPop ERROR: Not expecting immediate operand \n"
                log.debug(sDbg)
        else:
            sDbg ="\nERROR: Not expecting more than one source operand \n"
            log.debug(sDbg)
                     
    '''
    XCHG-Exchange Register/Memory with Register
    Example:
    Inst_category=11, Disassembly: xchg %eax, %esp
    src_operand_num=2:
    width=32, rw=1, type=2, ea_string=ESP
    width=32, rw=1, type=2, ea_string=EAX
    dest_operand_num=2:
    width=32, rw=1, type=2, ea_string=ESP
    width=32, rw=1, type=2, ea_string=EAX
    end results:
    eax <->esp
    '''
    def TaintPropogateXCHG(self, instInfo, instRec):
        sDbg = "Taint propagating unary: %s\n" %(instInfo.attDisa)
        log.debug(sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if(instInfo.n_src_operand!=2 or instInfo.n_dest_operand!=2):
            if (self.bDebug==True):
                #instInfo.printInfo()
                print("Is this XCHG? %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand))
            return
        
        ### TODO: complete all cases
        if(instInfo.src_operands[0]._type == REGISTER):
            normalizedSrcReg0Names = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[0]._ea).strip("b'"), instInfo.src_operands[0]._width_bits/8,tid)
        elif (instInfo.src_operands[0]._type == MEMORY):
            if (self.bDebug==True):
                print("XCHG Mem Mode not implemented %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand))
            return
        
        if(instInfo.src_operands[1]._type == REGISTER):
            normalizedSrcReg1Names = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[0]._ea).strip("b'"), instInfo.src_operands[1]._width_bits/8,tid)
        elif (instInfo.src_operands[1]._type == MEMORY):
            if (self.bDebug==True):
                print("XCHG Mem Mode not implemented %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand))
            return        

        srcLen = len(normalizedSrcReg0Names)
        for j in range(srcLen):
            if (normalizedSrcReg0Names[j] in self.dynamic_taint and normalizedSrcReg1Names[j] in self.dynamic_taint):
                #  Corresponding Reg0 and Reg1 byte will taint each other
                taint0 = Taint(REGISTER_TAINT,normalizedSrcReg0Names[j], instRec.currentInstSeq,tid,instStr)
                Taint.uid2Taint[taint0.tuid]= taint0
                srcTaint0 = self.dynamic_taint[normalizedSrcReg1Names[j]]
                taint0.addTaintDSources(srcTaint0)                                

                taint1 = Taint(REGISTER_TAINT,normalizedSrcReg1Names[j], instRec.currentInstSeq,tid,instStr)
                Taint.uid2Taint[taint1.tuid]= taint1
                srcTaint1 = self.dynamic_taint[normalizedSrcReg0Names[j]]
                taint1.addTaintDSources(srcTaint1)                                
            elif (normalizedSrcReg0Names[j] in self.dynamic_taint):
                #taint R1
                taint1 = Taint(REGISTER_TAINT,normalizedSrcReg1Names[j], instRec.currentInstSeq,tid,instStr)
                Taint.uid2Taint[taint1.tuid]= taint1
                srcTaint1 = self.dynamic_taint[normalizedSrcReg0Names[j]]
                taint1.addTaintDSources(srcTaint1)                                
                #untain R0
                self.dynamic_taint[normalizedSrcReg0Names[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                sDbg = "UNTAINT %s\n" %(self.dynamic_taint[normalizedSrcReg0Names[j]])
                log.debug(sDbg)
                del self.dynamic_taint[normalizedSrcReg0Names[j]]
            elif (normalizedSrcReg1Names[j] in self.dynamic_taint):
                #taint R0, untaint R1
                taint0 = Taint(REGISTER_TAINT,normalizedSrcReg0Names[j], instRec.currentInstSeq,tid,instStr)
                Taint.uid2Taint[taint0.tuid]= taint0
                srcTaint0 = self.dynamic_taint[normalizedSrcReg0Names[j]]
                taint1.addTaintDSources(srcTaint0)                                
                #untain R1
                self.dynamic_taint[normalizedSrcReg1Names[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                sDbg = "UNTAINT %s\n" %(self.dynamic_taint[normalizedSrcReg1Names[j]])
                log.debug(sDbg)
                del self.dynamic_taint[normalizedSrcReg1Names[j]]
                
    def TaintPropogateUnary(self, instInfo, instRec):
        sDbg = "Taint propagating unary: %s\n" %(instInfo.attDisa)
        sDbg = instInfo.getDebugInfo()
        log.debug(sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if(instInfo.n_src_operand!=1 or instInfo.n_dest_operand!=1):
            if (str(instInfo.attDisa).find("xchg")!=-1):
                self.TaintPropogateXCHG(instInfo, instRec)
            elif (self.bDebug==True):
                sDbg = instInfo.getDebugInfo()
                log.debug(sDbg)
                #print("Taint propagating unary is NOT Unary!!! %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand))
        
            
        for i in range(instInfo.n_src_operand):
            if(instInfo.src_operands[i]._type == REGISTER):
                normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[i]._ea).strip("b'"), instInfo.src_operands[i]._width_bits/8,tid)
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
                                normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
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
                            elif(instInfo.dest_operands[k]._type == MEMORY):
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
                                normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
                                # for 1-To-1 mode
                                if(normalizedDestRegNames[j] in self.dynamic_taint): 
                                    sDbg = "UNTAINT %s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                                    log.debug(sDbg)
                                    del self.dynamic_taint[normalizedDestRegNames[j]]                            
                            elif(instInfo.dest_operands[k]._type == MEMORY):
                                destAddress = instRec.currentWriteAddr
                                if(destAddress+j in self.dynamic_taint):
                                    self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                                    sDbg = "UNTAINT %s\n" %(self.dynamic_taint[destAddress+j])
                                    log.debug(sDbg)
                                    del self.dynamic_taint[destAddress+j]
                        
            elif (instInfo.src_operands[i]._type == MEMORY):
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
                                normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
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

                            elif(instInfo.dest_operands[k]._type == MEMORY):
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
                                normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
                                # for 1-To-1 mode
                                if(normalizedDestRegNames[j] in self.dynamic_taint): 
                                    self.dynamic_taint[normalizedDestRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                                    sDbg = "UnTAINT:%s\n" %(self.dynamic_taint[normalizedDestRegNames[j]])
                                    log.debug(sDbg)
                                    del self.dynamic_taint[normalizedDestRegNames[j]]

                            elif(instInfo.dest_operands[k]._type == MEMORY):
                                destAddress = instRec.currentWriteAddr
                                if(destAddress+j in self.dynamic_taint):
                                    self.dynamic_taint[destAddress+j].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                                    sDbg = "DETAINT %s" %(self.dynamic_taint[destAddress+j])
                                    log.debug(sDbg)
                                    del self.dynamic_taint[destAddress+j]
            else:
                continue
            
    '''
    Handle cases like AND, OR, XOR which has a byte to byte mapping, but not a replacement(like move)
    '''
    def TaintPropogateUnion(self, instInfo, instRec):
        sDbg = "Taint propagating logical union: %s\n" %(instInfo.attDisa)
        log.debug(sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
                    
        for i in range(instInfo.n_src_operand):
            if(instInfo.src_operands[i]._type == REGISTER):
                normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[i]._ea).strip("b'"), instInfo.src_operands[i]._width_bits/8,tid)
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
                                normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
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
                            elif(instInfo.dest_operands[k]._type == MEMORY):
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
                            #NO UNTAINT when Src is not Tainted                        
            elif (instInfo.src_operands[i]._type == MEMORY):
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
                                normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.dest_operands[k]._ea).strip("b'"), instInfo.dest_operands[k]._width_bits/8,tid)
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

                            elif(instInfo.dest_operands[k]._type == MEMORY):
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
                            #NO UNTAINT when Src is not Tainted    
            else:
                continue
            
            
            
    def TaintPropogateCmp(self, instInfo, instRec):
        if self.bDebug:
            print("Ignore CMP flags for now")
        return

    def TaintPropogateXOR(self, instInfo, instRec):
        sDbg = "Taint propagating XOR: %s\n" %(instInfo.attDisa)
        log.debug(sDbg)

        #handle special case first: when src and dest are both the same register         
        if(instInfo.n_src_operand!=2):
            if (self.bDebug==True):
                print("Two source operands are expected!!!")
            return

        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        
        if((instInfo.src_operands[0]._type == REGISTER) and (instInfo.src_operands[1]._type == REGISTER)):
            if(instInfo.src_operands[0]._ea.find(instInfo.src_operands[1]._ea)!=-1):# the same registers
                if (self.bDebug==True):
                    print "Handle XOR Special case"
                normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[0]._ea).strip("b'"), instInfo.src_operands[0]._width_bits/8,tid)
                srcLen = len(normalizedSrcRegNames)
                for j in range(srcLen):
                    if (normalizedSrcRegNames[j] in self.dynamic_taint):
                        #detaint
                        self.dynamic_taint[normalizedSrcRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId) 
                        sDbg = "DETAINT %s" %(normalizedSrcRegNames[j])
                        log.debug(sDbg)
                        del self.dynamic_taint[normalizedSrcRegNames[j]]
                        if (self.bDebug==True):
                            print("Detaint %s" %normalizedSrcRegNames[j])
                return
            
        if (self.bDebug==True):
            print"Handle XOR normal case"
        self.TaintPropogateBinary(instInfo, instRec)

    def TaintPropogateOR(self, instInfo, instRec):
        sDbg = "Taint propagating OR: %s\n" %(instInfo.attDisa)
        log.debug(sDbg)

        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if((instInfo.src_operands[1]._type == IMMEDIATE)):
            if(int(instInfo.src_operands[1]._ea,16)==0xffffffff):
                if (self.bDebug==True):
                    print "Handle OR Special case(0xffffffff)" #simplified special case
                if (instInfo.src_operands[0]._type == REGISTER):
                    normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[0]._ea).strip("b'"), instInfo.src_operands[0]._width_bits/8,tid)
                    srcLen = (int)(instInfo.src_operands[1]._width_bits/8) # this is the immediate width
                    for j in range(srcLen): 
                        if (normalizedSrcRegNames[j] in self.dynamic_taint):
                            sDbg = "OR DETAINT %s" %(normalizedSrcRegNames[j])
                            log.debug(sDbg)
                            self.dynamic_taint[normalizedSrcRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                            del self.dynamic_taint[normalizedSrcRegNames[j]]
                            if (self.bDebug==True):
                                print("OR Detaint %s" %normalizedSrcRegNames[j])
                elif (instInfo.src_operands[0]._type == MEMORY):
                    destAddress = instRec.currentWriteAddr
                    nBytes = (int)(instInfo.src_operands[1]._width_bits/8) # this is the immediate width
                    for l in range(nBytes):
                        if(destAddress+l in self.dynamic_taint):
                            sDbg = "OR DETAINT %s" %(destAddress+l)
                            log.debug(sDbg)
                            self.dynamic_taint[destAddress+l].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                            del self.dynamic_taint[destAddress+l]
                            if (self.bDebug==True):
                                print("OR Detaint %s" %(destAddress+l))
            return

        if (self.bDebug==True):
            print("Taint OR normal cases!")        
        self.TaintPropogateUnion(instInfo, instRec)

    def TaintPropogateAND(self, instInfo, instRec):
        sDbg = "Taint propagating AND: %s\n" %(instInfo.attDisa)
        log.debug(sDbg)

        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if((instInfo.src_operands[1]._type == IMMEDIATE)):
            if(int(instInfo.src_operands[1]._ea,16)==0):
                if (self.bDebug==True):
                    print "Handle AND Special case(0)"
                if (instInfo.src_operands[0]._type == REGISTER):
                    normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[0]._ea).strip("b'"), instInfo.src_operands[0]._width_bits/8,tid)
                    srcLen = (int)(instInfo.src_operands[1]._width_bits/8) # this is the immediate width
                    for j in range(srcLen): 
                        if (normalizedSrcRegNames[j] in self.dynamic_taint):
                            sDbg = "AND DETAINT %s" %(normalizedSrcRegNames[j])
                            log.debug(sDbg)
                            self.dynamic_taint[normalizedSrcRegNames[j]].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                            del self.dynamic_taint[normalizedSrcRegNames[j]]
                            if (self.bDebug==True):
                                print("AND Detaint %s" %normalizedSrcRegNames[j])
                elif (instInfo.src_operands[0]._type == MEMORY):
                    destAddress = instRec.currentWriteAddr
                    nBytes = (int)(instInfo.src_operands[1]._width_bits/8) # this is the immediate width
                    for l in range(nBytes):
                        if(destAddress+l in self.dynamic_taint):
                            sDbg = "AND DETAINT %s" %(destAddress+l)
                            log.debug(sDbg)
                            self.dynamic_taint[destAddress+l].terminateTaint(instRec.currentInstSeq,instRec.currentThreadId)
                            del self.dynamic_taint[destAddress+l]
                            if (self.bDebug==True):
                                print("AND Detaint %s" %(destAddress+l))
            return
        
        if (self.bDebug==True):
            print("Taint AND normal cases!")
        self.TaintPropogateUnion(instInfo, instRec) #enhance 

    def TaintPropogateTEST(self, instInfo, instRec):
        sDbg = "Taint propagating TEST: %s\n" %(instInfo.attDisa)
        log.debug(sDbg)

        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        if (self.bDebug==True):
            print("Taint FLAG %s NOT IMPLEMENTED\n" %instInfo.attDisa)
    
    def TaintPropogateLogic(self, instInfo, instRec):
        sDbg = "Taint propagating logic: %s\n" %(instInfo.attDisa)
        log.debug(sDbg)

        if (str(instInfo.attDisa).find("xor")!=-1):
            self.TaintPropogateXOR(instInfo, instRec)
        elif (str(instInfo.attDisa).find("or")!=-1):
            self.TaintPropogateOR(instInfo, instRec)
        elif (str(instInfo.attDisa).find("and")!=-1):
            self.TaintPropogateAND(instInfo, instRec)
        elif (str(instInfo.attDisa).find("test")!=-1):
            self.TaintPropogateTEST(instInfo, instRec)
        else:
            if (self.bDebug==True):
                print("Taint %s NOT IMPLEMENTED\n" %instInfo.attDisa)
        
    def TaintPropogateBinary(self, instInfo, instRec):
        sDbg = "Taint propagating binary %s:\n" %(instInfo.attDisa)
        log.debug(sDbg)
        tid = instRec.currentThreadId
        instStr = str(instInfo.attDisa).strip("b'")
        #if self.bDebug:
        #    print("Taint propagating binary: %s, nsrc = %d, ndest=%d" %(instInfo.attDisa,instInfo.n_src_operand,instInfo.n_dest_operand))
        if(str(instInfo.attDisa).find("cmp")!=-1):
            return self.TaintPropogateCmp(instInfo, instRec)
            
        for i in range(instInfo.n_dest_operand):
            if(instInfo.dest_operands[i]._type == REGISTER):
                normalizedDestRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.dest_operands[i]._ea).strip("b'"), instInfo.dest_operands[i]._width_bits/8,tid)
                destLen = len(normalizedDestRegNames)
                for j in range(destLen):
                    taint =None
                    for k in range(instInfo.n_src_operand):
                        if(instInfo.src_operands[k]._type == REGISTER):
                            if(str(instInfo.dest_operands[k]._ea).strip("b'").lower()== 'eflags'):
                                continue
                            normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[k]._ea).strip("b'"), instInfo.src_operands[k]._width_bits/8,tid)
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
                        elif(instInfo.src_operands[k]._type == MEMORY):
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

            elif (instInfo.dest_operands[i]._type == MEMORY):
                nBytes = int(instInfo.dest_operands[i]._width_bits/8)
                destAddress = instRec.currentWriteAddr
                for j in range(nBytes):
                    taint =None
                    for k in range(instInfo.n_src_operand):
                        if(instInfo.src_operands[k]._type == REGISTER):
                            if(str(instInfo.dest_operands[k]._ea).strip("b'").lower()== 'eflags'):
                                continue
                            normalizedSrcRegNames = self.x86ISA.getNormalizedX86RegisterNames(str(instInfo.src_operands[k]._ea).strip("b'"), instInfo.src_operands[k]._width_bits/8,tid)
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
                        elif(instInfo.src_operands[k]._type == MEMORY):
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
