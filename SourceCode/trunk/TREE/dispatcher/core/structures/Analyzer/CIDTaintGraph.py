'''

This is the thread map for CBASS.Each thread has a different set of context:registers, stack  
Inputs:
    -- thread id
    -- register values 
 Output:
   -- Read or write corresponding register set based on their thread context
   
Borrowed x86 state model from Valgrind VEX library:
Vex's representation of the x86 CPU state defined in header file
libvex_guest_x86.h  
/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2004-2010 OpenWorks LLP
      info@open-works.net

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   The GNU General Public License is contained in the file COPYING.

   Neither the names of the U.S. Department of Energy nor the
   University of California nor the names of its contributors may be
   used to endorse or promote products derived from this software
   without prior written permission.
*/

The essential c structure of the thread state is as follows:

typedef
   struct {
      UInt  guest_EAX;         /* 0 */
      UInt  guest_ECX;
      UInt  guest_EDX;
      UInt  guest_EBX;
      UInt  guest_ESP;
      UInt  guest_EBP;
      UInt  guest_ESI;
      UInt  guest_EDI;         /* 28 */

      /* 4-word thunk used to calculate O S Z A C P flags. */
      UInt  guest_CC_OP;       /* 32 */
      UInt  guest_CC_DEP1;
      UInt  guest_CC_DEP2;
      UInt  guest_CC_NDEP;     /* 44 */
      /* The D flag is stored here, encoded as either -1 or +1 */
      UInt  guest_DFLAG;       /* 48 */
      /* Bit 21 (ID) of eflags stored here, as either 0 or 1. */
      UInt  guest_IDFLAG;      /* 52 */
      /* Bit 18 (AC) of eflags stored here, as either 0 or 1. */
      UInt  guest_ACFLAG;      /* 56 */

      /* EIP */
      UInt  guest_EIP;         /* 60 */

      /* FPU */
      ULong guest_FPREG[8];    /* 64 */
      UChar guest_FPTAG[8];   /* 128 */
      UInt  guest_FPROUND;    /* 136 */
      UInt  guest_FC3210;     /* 140 */
      UInt  guest_FTOP;       /* 144 */

      /* SSE */
      UInt  guest_SSEROUND;   /* 148 */
      U128  guest_XMM0;       /* 152 */
      U128  guest_XMM1;
      U128  guest_XMM2;
      U128  guest_XMM3;
      U128  guest_XMM4;
      U128  guest_XMM5;
      U128  guest_XMM6;
      U128  guest_XMM7;

      /* Segment registers. */
      UShort guest_CS;
      UShort guest_DS;
      UShort guest_ES;
      UShort guest_FS;
      UShort guest_GS;
      UShort guest_SS;
      /* LDT/GDT stuff. */
      HWord  guest_LDT; /* host addr, a VexGuestX86SegDescr* */
      HWord  guest_GDT; /* host addr, a VexGuestX86SegDescr* */

      /* Emulation warnings */
      UInt   guest_EMWARN;

      /* For clflush: record start and length of area to invalidate */
      UInt guest_TISTART;
      UInt guest_TILEN;

      /* Used to record the unredirected guest address at the start of
         a translation whose start has been redirected.  By reading
         this pseudo-register shortly afterwards, the translation can
         find out what the corresponding no-redirection address was.
         Note, this is only set for wrap-style redirects, not for
         replace-style ones. */
      UInt guest_NRADDR;

      /* Used for Darwin syscall dispatching. */
      UInt guest_SC_CLASS;

      /* Needed for Darwin (but mandated for all guest architectures):
         EIP at the last syscall insn (int 0x80/81/82, sysenter,
         syscall).  Used when backing up to restart a syscall that has
         been interrupted by a signal. */
      UInt guest_IP_AT_SYSCALL;

      /* Padding to make it have an 16-aligned size */
      UInt padding1;
      UInt padding2;
      UInt padding3;
   }
   VexGuestX86State;
   
 * @author Nathan Li
 * 
 */
'''
from SymbolicTypes import DQWORD, QWORD,DWORD,WORD, BYTE
from IRmemory import IRMemory,InvalidMemorySize,IRConcolicMemory
from IRoperator import extract, replace
from SymbolicTypes import SymbolicValue, InputVariable
import logging
import struct
    
log = logging.getLogger('cbass')


class UnImplemented(Exception):
    pass

class InvalidRegisterName(Exception):
    pass

class InvalidFlagValue(Exception):
    pass

class InvalidFlag(Exception):
    pass

        
class VexX86ThreadState(object):
    #general registers            
    OFFSET_x86_EAX = 0
    OFFSET_x86_ECX = 4
    OFFSET_x86_EDX = 8
    OFFSET_x86_EBX = 12
    OFFSET_x86_ESP = 16
    OFFSET_x86_EBP = 20
    OFFSET_x86_ESI = 24
    OFFSET_x86_EDI = 28
    
    # 4-word thunk used to calculate O S Z A C P flags. 
    OFFSET_x86_CC_OP = 32
    OFFSET_x86_CC_DEP1 = 36
    OFFSET_x86_CC_DEP2 = 40
    OFFSET_x86_CC_NDEP = 44
    #The D flag is stored here, encoded as either -1 or +1 
    OFFSET_x86_DFLAG = 48
    #Bit 21 (ID) of eflags stored here, as either 0 or 1. 
    OFFSET_x86_IDFLAG = 52
    #Bit 18 (AC) of eflags stored here, as either 0 or 1.
    OFFSET_x86_ACFLAG = 56 
    
    # EIP 
    OFFSET_x86_EIP = 60

    #Sub register offsets, calculated manually
    OFFSET_x86_AX=OFFSET_x86_EAX
    OFFSET_x86_AL=OFFSET_x86_EAX
    OFFSET_x86_AH=OFFSET_x86_EAX+1
    OFFSET_x86_BX=OFFSET_x86_EBX
    OFFSET_x86_BL=OFFSET_x86_EBX
    OFFSET_x86_BH=OFFSET_x86_EBX+1
    OFFSET_x86_CX=OFFSET_x86_ECX
    OFFSET_x86_CL=OFFSET_x86_ECX
    OFFSET_x86_CH=OFFSET_x86_ECX+1
    OFFSET_x86_DX=OFFSET_x86_EDX
    OFFSET_x86_DL=OFFSET_x86_EDX
    OFFSET_x86_DH=OFFSET_x86_EDX+1
    OFFSET_x86_DI=OFFSET_x86_EDI
    OFFSET_x86_SI=OFFSET_x86_ESI
    OFFSET_x86_BP=OFFSET_x86_EBP
    OFFSET_x86_SP=OFFSET_x86_ESP

    """
    Represents the memory of a little endian system.

    BYTE = 1
    WORD = BYTE * 2
    DWORD = WORD * 2
    
    QWORD = DWORD * 2
    DQWORD = QWORD * 2
    
    The maximum value representable in a 32-bit integer
    MAXIMUM_32 = 2 ** 32 - 1
    """
    
    def __init__(self):
        self.max_range = {
            BYTE : 2**8 - 1,
            WORD : 2**16 - 1,
            DWORD : 2**32 - 1,
            QWORD : 2**64 - 1,
            DQWORD : 2**128 - 1
        }
        self.x86Reg_state = IRConcolicMemory()
    
    def init_from_snapshot(self,snapsize,snapbytes):
        bytes = snapbytes.split("_")
        for i in range(snapsize-1):
            #print ("i=%d bytes=%x" %(i,int(bytes[i],16)))
            self.x86Reg_state.set_byte(i, int(bytes[i],16))
            
    def get_regname_from_offset(self,offset):    
        name = None
        
        if(offset == self.OFFSET_x86_EAX):
            name = "EAX"
        elif (offset == self.OFFSET_x86_EAX+1):
            name = "AH"
        elif (offset == self.OFFSET_x86_EBX):
            name = "EBX"
        elif (offset == self.OFFSET_x86_EBX+1):
            name = "BH"
        elif (offset == self.OFFSET_x86_ECX):
            name = "ECX"
        elif (offset == self.OFFSET_x86_ECX+1):
            name = "CH"
        elif (offset == self.OFFSET_x86_EDX):
            name = "EDX"
        elif (offset == self.OFFSET_x86_EDX+1):
            name = "DH"
        elif (offset == self.OFFSET_x86_EDI):
            name = "EDI"
        elif (offset == self.OFFSET_x86_ESI):
            name = "ESI"
        elif (offset == self.OFFSET_x86_EBP):
            name = "EBP"
        elif (offset == self.OFFSET_x86_ESP):
            name = "ESP"
        return name
    
    def get_value_from_offset(self, offset,size):
        print ("offset=%d, size=%d" %(offset, size))
        return self.x86Reg_state.get_addr_val(offset, size)

    def set_value_at_offset(self, offset, value, size):
        self.x86Reg_state.set_addr_val(offset, value, size)
            
 