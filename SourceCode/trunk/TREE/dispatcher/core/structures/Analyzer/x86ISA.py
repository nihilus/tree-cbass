'''
This is x86 instruction set specific properties

 * @author Nathan Li
 *
'''
class X86ISA:
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

    def __init__(self):
        pass

    def getNormalizedX86EFlagName(self,tid):
        return "eflags"+"_"+str(tid)        
        
    def getNormalizedX86RegisterNames(self,regname, width_bytes, tid):
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
            
            for i in range(int(width_bytes)):
                normalizedNames.append(str(regname.lower())+"_"+str(i)+"_"+str(tid))
        return normalizedNames
        
        
        
