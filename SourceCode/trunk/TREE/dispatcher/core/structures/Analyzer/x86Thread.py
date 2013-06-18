'''

This is the thread map for CBASS.Each thread has a different set of context:registers, stack  
Inputs:
    -- thread id
    -- register values 
 Output:
   -- Read or write corresponding register set based on their thread context
   
 * @author Nathan Li
 *
'''
import logging

X86 = 1
X64 = 2
ARM = 3
PPC = 4
MIPS = 5
    
log = logging.getLogger('TREE')

class NotImplemented(Exception):
    pass

class InvalidRegisterName(Exception):
    pass

class InvalidFlagValue(Exception):
    pass

class InvalidFlag(Exception):
    pass

class X86Thread:
    
    def __init__(self):
        self.PIN_EDI = 12
        self.PIN_ESI = 13
        self.PIN_EBP = 14
        self.PIN_ESP = 15
        self.PIN_EBX = 16
        self.PIN_EDX = 17
        self.PIN_ECX = 18
        self.PIN_EAX = 19
        self.PIN_SS = 21
        self.PIN_DS = 22
        self.PIN_ES = 23    
        self.PIN_FS = 24
        self.PIN_EFLAGS = 26
        self.PIN_EIP = 27
        self.PIN_FSBASE = 173
        #PIN_FSBASE needs to treat as memory
        
        
        
    def is_eflags(self,regname):    
        if regname.upper() == "ZF" or regname.upper() == "CF" or regname.upper() == "SF" or regname.upper() == "OF":
            return True
        else:
            return False

    def get_eflag_id(self,regname):    
        if regname.upper() == "ZF":
            return self.ZF
        elif regname.upper() == "CF":
            return self.CF
        elif regname.upper() == "SF":
            return self.SF 
        elif regname.upper() == "OF":
            return self.OF
        else:
            return None

    def get_reg_name(self, PIN_RegID):
        if PIN_RegID == self.PIN_EAX:
            return "eax"
        elif PIN_RegID == self.PIN_EBX:
            return "ebx"
        elif PIN_RegID == self.PIN_ECX:
            return "ecx"
        elif PIN_RegID == self.PIN_EDX:
            return "edx"
        elif PIN_RegID == self.PIN_ESI:
            return "esi"
        elif PIN_RegID == self.PIN_EDI:
            return "edi"
        elif PIN_RegID == self.PIN_ESP:
            return "esp"
        elif PIN_RegID == self.PIN_EBP:
            return "ebp"
        elif PIN_RegID == self.PIN_EIP:
            return "eip"
        elif PIN_RegID == self.PIN_EFLAGS:
            return "eflags"
        elif PIN_RegID ==self.PIN_SS:
            return "ss"
        elif PIN_RegID ==self.PIN_DS:
            return "ds"
        elif PIN_RegID ==self.PIN_ES:
            return "es"
        elif PIN_RegID ==self.PIN_FS:
            return "fs"
        elif PIN_RegID == self.PIN_FSBASE:
            return "fsbase"                        
        else:
            return None
        
    def get_register_id(self,regname):
        if regname.upper() == "EAX":
            return self.PIN_EAX
        elif regname.upper() == "EBX":
            return self.PIN_EBX
        elif regname.upper() == "ECX":
            return self.PIN_ECX
        elif regname.upper() == "EDX":
            return self.PIN_EDX
        elif regname.upper() == "ESI":
            return self.PIN_ESI
        elif regname.upper() == "EDI":
            return self.PIN_EDI
        elif regname.upper() == "ESP":
            return self.PIN_ESP
        elif regname.upper() == "EBP":
            return self.PIN_EBP
        elif regname.upper() =="EIP":
            return self.PIN_EIP
        elif regname.upper() =="EFLAGS":
            return self.PIN_EFLAGS
        elif regname.upper() =="FSBASE":
            return self.PIN_FSBASE                        
        else:
            return None

