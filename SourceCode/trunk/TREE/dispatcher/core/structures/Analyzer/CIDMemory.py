'''

This is the memory map for CBASS.
All threads share same memory space. 
Memory state is modeled as a dictionary of <address, value>, where value can be either concrete or symbolic   
Inputs:
    -- address
    -- value 
 Output:
   -- Read or write corresponding memory state based on the address 
   
 * @author Nathan Li
 * 
 */
'''
import os
import struct
import logging
from collections import namedtuple

log = logging.getLogger('CIDATA')

DQWORD = 16
QWORD = 8
DWORD = 4
WORD = 2
BYTE = 1
 
class ReadUninitializedMemory(Exception):
    pass

class InvalidMemorySize(Exception):
    pass

class InvalidMemoryValue(Exception):
    pass

class ConcreteMemory(object):
    
    """
    Represents the memory of a little endian system.
    """
    # The maximum value representable in a 32-bit integer
    MAXIMUM_32 = 2 ** 32 - 1

    def __init__(self):
        self.maximum = {
            BYTE : 2**8 - 1,
            WORD : 2**16 - 1,
            DWORD : 2**32 - 1,
            QWORD : 2**64 - 1,
            DQWORD : 2**128 - 1
        }

        self.mem = {}
   
    def get_words(self, addr, nbytes):
        nodes = []
        try:
            for offset in range(0, nbytes):
                nodes.append(self.__getitem__(addr + offset))
        except Exception as e:
            raise e

        val = nodes[0]

        for x in range(1, nbytes):
            val |= nodes[x] << (8 * x)

        return val
           
   
    def get_dqword(self, addr):
        return self.get_words(addr, DQWORD)

    def get_qword(self, addr):
        return self.get_words(addr, QWORD)

    def get_dword(self, addr):
        return self.get_words(addr, DWORD)

    def get_word(self, addr):
        try:
            b0 = self.__getitem__(addr)
            b1 = self.__getitem__(addr + 1)
        except Exception as e:
            raise e

        val =  b0 | b1 << 8    
        return val

    def get_byte(self, addr):

        try:
            b0 = self.__getitem__(addr)
        except Exception as e:
            raise e
        return b0

    def get_addr_val(self, addr, size):
        if size == DQWORD:
            return self.get_dqword(addr)
        elif size == QWORD:
            return self.get_qword(addr)
        elif size == DWORD:
            return self.get_dword(addr)
        elif size == WORD:
            return self.get_word(addr)
        elif size == BYTE:
            return self.get_byte(addr)
        else:
            raise InvalidMemorySize("Invalid memory size 0x%x" % size)

    def set_words(self, addr, val, nbytes):
    
        if (isinstance(val, int)) and val > self.maximum[nbytes]:
            raise InvalidMemoryValue(("value 0x%x out of range") % (val))
         
        try:
            for idx in range(0, nbytes):
                offset = idx * 8
                self.__setitem__(addr + idx, val >> offset & 0xff)
        except Exception as e:
            raise e

    def set_dqword(self, addr, val):
        return self.set_words(addr, val, DQWORD)

    def set_qword(self, addr, val):
        return self.set_words(addr, val, QWORD)

    def set_dword(self, addr, val):
        return self.set_words(addr, val, DWORD)

    def set_word(self, addr, val):
        if (isinstance(val, int)) and val > 0xffff:
            raise InvalidMemoryValue(("value 0x%x out of word range") % val)

        try:
            self.__setitem__(addr, val & 0xff)
            self.__setitem__(addr + 1, val >> 8 & 0xff)
        except Exception as e:
            raise e

    def set_byte(self, addr, val):
        if (isinstance(val, int)) and val > 0xff:
            raise InvalidMemoryValue(("value 0x%x out of byte range") % val)

        try:
            self.__setitem__(addr, val)
        except Exception as e:
            raise e

    def set_addr_val(self, addr, val, size):
        if size == DQWORD:
            self.set_dqword(addr, val)
        elif size == QWORD:
            self.set_qword(addr, val)
        elif size == DWORD:
            self.set_dword(addr, val)
        elif size == WORD:
            self.set_word(addr, val)
        elif size == BYTE:
            self.set_byte(addr, val)
        else:
            raise InvalidMemorySize("Invalid size 0x%x" % size)

