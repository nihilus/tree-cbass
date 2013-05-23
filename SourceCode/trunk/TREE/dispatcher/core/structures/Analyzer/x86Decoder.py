'''

This is the x86Decode for CBASS.
Using ctype to interact with XED based C module  
Inputs:
    -- instruction length
    -- instruction encoded bytes
 Output:
   -- A structure to describe the instruction source, destination operands 
 including explicit and implicit  
 
 * All Intel Architecture instructions are encoded using subsets of the general
 * machine instruction format Instructions consist of optional instruction
 * prefixes (in any order), primary opcode bytes (up to three bytes), an
 * addressing-form specifier (if required) consisting of the ModR/M byte and
 * sometimes the SIB (Scale-Index-Base) byte, a displacement (if required), and
 * an immediate data field (if required).
 * 
 * We use XED library from Intel as x86 instruction semantic decoder and invoke
 * the library from python using ctype support.
  
 * @author Nathan Li
 *  
'''
import logging
import struct
from ctypes.util import *
from ctypes import *
import ctypes

#instruction constants
MAX_OPERAND = 8
MAX_DIS_LEN = 128

#operand type enum
INVALID=0
IMMEDIATE=1
REGISTER=2
MEMORY=3
LAST=4

#host OS
WINDOWS = 1
LINUX = 2

class Operand(Structure):
    _fields_ = [("_width_bits", c_int),
                  ("_rw", c_int),
                  ("_type", c_int),
                  ("_ea",c_char * MAX_DIS_LEN)]  
    def printInfo(self):
        print("width=%d, rw=%d, type=%d, ea_string=%s" %(self._width_bits,self._rw,self._type,self._ea))
        
class instDecode(Structure):
    _fields_ = [("n_src_operand", c_int),
                ("n_dest_operand", c_int),
                ("src_operands", Operand * MAX_OPERAND),
                ("dest_operands", Operand * MAX_OPERAND),
                ("inst_category", c_int),
                ("operand_width", c_int),
                ("effective_operand_width", c_int),
                ("address_width", c_int),
                ("stack_address_width", c_int),
                ("attDisa",c_char * MAX_DIS_LEN)]
    
    def printInfo(self):
        print("Inst_category=%d, Disassembly: %s\n"  %(self.inst_category,self.attDisa))
        print("src_operand_num=%d:\n" %(self.n_src_operand))
        for i in range(self.n_src_operand):
            self.src_operands[i].printInfo()

        print("\ndest_operand_num=%d:\n" %(self.n_dest_operand))
        for i in range(self.n_dest_operand):
            self.dest_operands[i].printInfo()        
              
class x86Decoder(object):
    def __init__(self, process_bits,target_bits,target_OS):
        self.process_bits = process_bits
        self.target_bits = target_bits
        self.target_os = WINDOWS
        if (target_OS is not None):
            self.target_os = target_OS            
        self.decode_lib = None
        self.decode_fun = None
        if (process_bits==32):
            if (self.target_os == WINDOWS):
                dll_name = "xdecoder_32.dll"
                dllabspath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + dll_name
                self.decode_lib=ctypes.windll.LoadLibrary(dllabspath)
            elif (self.target_os == LINUX):
                dll_name = "xdecoder_32.so"
                dllabspath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + dll_name
                print("%s" %dllabspath)
                self.decode_lib=ctypes.cdll.LoadLibrary(dllabspath)
        elif process_bits==64:
            self.decode_lib=cdll.xdecoder_64
        if(self.decode_lib !=None):
            self.decode_fun = self.decode_lib.decode
        else:
            return None
        
    def decode_inst(self,instLen, pInstBytes, pInstDecode):
        nRes = 0
        if(self.decode_fun!=None):
            nRes = self.decode_fun(self.target_bits, instLen, pInstBytes, pInstDecode)
            return nRes
        else:
            print("NULL decode function!!!")
            return 0
        
