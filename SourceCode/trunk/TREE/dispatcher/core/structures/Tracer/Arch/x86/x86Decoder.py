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
INDIRECT=3
LAST=4

class Operand(Structure):

    _fields_ = [("_width_bits", c_int),
                  ("_rw", c_int),
                  ("_type", c_int),
                  ("_ea",c_char * MAX_DIS_LEN)]
        
    def printInfo(self,logger):
        logger.debug("width=%d, rw=%d, type=%d, ea_string=%s" %(self._width_bits,self._rw,self._type,self._ea))
        
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
    
    def printInfo(self,logger):
        logger.debug("src_operand_num=%d:\n" %(self.n_src_operand))
        for i in range(self.n_src_operand):
            self.src_operands[i].printInfo(logger)

        logger.debug("\ndest_operand_num=%d:\n" %(self.n_dest_operand))
        for i in range(self.n_dest_operand):
            self.dest_operands[i].printInfo(logger)
        
        logger.debug("Disassembly: %s\n"  %(self.attDisa))
              
class x86Decoder(object):
    def __init__(self, isa_bits):
        self.logger = logging.getLogger('IDATrace')
        self.isa_bits = isa_bits
        self.winlib = None
        self.decode_fun = None
        if (isa_bits==32):
            #this method allows calling the dll from its actual path not just from system32
            dll_name = "xdecoder_32.dll"
            dllabspath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + dll_name
            #self.winlib=windll.LoadLibrary("C:\\Users\\xing\\Downloads\\trace\\xdecoder_32.dll")
            self.winlib=ctypes.windll.LoadLibrary(dllabspath)
        elif isa_bits==64:
            #When the 64 bits decoder is available
            dll_name = "xdecoder_64.dll"
            dllabspath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + dll_name
            self.winlib=ctypes.windll.LoadLibrary(dllabspath)
        if(self.winlib !=None):
            print(self.winlib)
            self.decode_fun = self.winlib.decode
            self.logger.info(self.decode_fun)
        else:
            return None
        
    def decode_inst(self,instLen, pInstBytes, pInstDecode):
        nRes = 0
        if(self.decode_fun!=None):
            #print("decode parameters:instLen=%d, pINstBytes=0x%x, pBuffer=0x%x" %(c_int(instLen), pInstBytes, addressof(pInstDecode)))
            self.logger.debug("decode parameters:isa_bits= %d, instLen=%d, pINstBytes=, pBuffer=" %(self.isa_bits, instLen))

            nRes = self.decode_fun(self.isa_bits, instLen, pInstBytes, pInstDecode)
                
            #pInfo = cast(pInstDecode, POINTER(instDecode))
            #print("decode result=%d, n_src_operand = %d" %(nRes,pInfo.__getattribute__('n_src_operand')))
            return nRes
        else:
            self.logger.error("NULL decode function!!!")
            return 0
        
