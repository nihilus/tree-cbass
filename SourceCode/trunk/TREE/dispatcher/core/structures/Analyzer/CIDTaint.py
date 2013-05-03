'''

This is the basic taint class for CBASS. 
   
 * @author Nathan Li
 * 
 */
'''
import logging
import struct
    
log = logging.getLogger('CIDATA')

INPUT_TAINT=-1
REGISTER_TAINT = 0
MEMORY_TAINT = 1
BRANCH_TAINT = 2
tuid=1

class Taint(object):
      
    uid2Taint = {}        
    visited = set()
       
    def __init__(self, taintType, taintAddress,creatorSequence,creatorThread, creatorInstAmenic, directInput=False):
        global tuid
        self.tuid = tuid
        tuid = tuid+1
        self.bDirectInput = directInput
        self.taintType= taintType
        self.taintAddress = taintAddress
        self.creatorSequence = creatorSequence
        self.creatorInstAmenic = creatorInstAmenic
        self.creatorThread = creatorThread
        self.cSources =[]
        self.dSources =[]
        self.terminatorInstruction = None
        self.terminatorThread = None
        self.InputFunctionCallerAddress = None

    def __eq__(self, other):
        if other==None:
            return False
        else:
            return self.tuid == other.tuid

    def __lt__(self, other):
        return self.tuid < other.tuid

    def addTaintCSources(self, taintSource):
        if(self.cSources.__contains__(taintSource)== False):
            self.cSources.append(taintSource)

    def addTaintDSources(self, taintSource):
        if(self.dSources.__contains__(taintSource)== False):
            self.dSources.append(taintSource)
        
    def terminateTaint(self,terminatorInstructionLine, terminatorThread):
        self.terminatorInstruction = terminatorInstructionLine
        self.terminatorThread = terminatorThread

    def setCreatorSequence(self, creatorSequence):
        self.creatorSequence = creatorSequence

    def setInputFunctionCaller(self, InputCallerAddress):
        if self.bDirectInput:
            self.InputFunctionCallerAddress = InputCallerAddress

        
    def __str__(self):
        taintStr ="[%s]" %(self.tuid)
        
        if(self.taintType == REGISTER_TAINT):
            taintStr =taintStr+"reg_"
        elif(self.taintType == MEMORY_TAINT):
            taintStr =taintStr+"mem_"
        elif(self.taintType == INPUT_TAINT):
            taintStr =taintStr+"in_"            
        else:
            taintStr =taintStr+"bc_"
        
        if isinstance(self.taintAddress, int):
            taintStr = taintStr+hex(self.taintAddress)+"["+hex(self.creatorSequence)+":"+hex(self.creatorThread)+"]"
        else:
            taintStr = taintStr+str(self.taintAddress)+"["+hex(self.creatorSequence)+":"+hex(self.creatorThread)+"]"
            
        if(self.terminatorInstruction!=None and self.terminatorThread !=None):
            taintStr = taintStr+"["+hex(self.terminatorInstruction)+":"+hex(self.terminatorThread)+"]"
        
        if(self.bDirectInput==True):
            taintStr = taintStr + "<-"+hex(self.InputFunctionCallerAddress)+":"+hex(self.creatorInstAmenic)
            return taintStr
        
        return taintStr
#        taint_tree = ""
#       if(len(self.taintSources)>0):        
#            taint_tree = "\n".join([("\t" + str(t)) for t in self.taintSources])
        #        return "".join(["%s<-%s" % (taintStr,self.creatorInstAmenic), "\n", taint_tree])

    def taint_tree(self, level=1):
        taintStr ="[%s]" %(self.tuid)
        
        if(self.taintType == REGISTER_TAINT):
            taintStr =taintStr+"reg_"
        elif(self.taintType == MEMORY_TAINT):
            taintStr =taintStr+"mem_"
        elif(self.taintType == INPUT_TAINT):
            taintStr =taintStr+"in_"                 
        else:
            taintStr =taintStr+"bc_"
            
        if isinstance(self.taintAddress, int):
            taintStr = taintStr+hex(self.taintAddress)+"["+hex(self.creatorSequence)+":"+hex(self.creatorThread)+"]"
        else:
            taintStr = taintStr+str(self.taintAddress)+"["+hex(self.creatorSequence)+":"+hex(self.creatorThread)+"]"
            
        if(self.terminatorInstruction!=None and self.terminatorThread !=None):
            taintStr = taintStr+"["+hex(self.terminatorInstruction)+":"+hex(self.terminatorThread)+"]"
        
        if(self.bDirectInput==True):
            taintStr = taintStr + "<-"+hex(self.InputFunctionCallerAddress)+":"+hex(self.creatorInstAmenic)
            return taintStr
        
        taint_dtree = None
        if(len(self.dSources)>0):        
            taint_dtree = "\n{D}".join([("\t" * level + t.taint_tree(level+1)) for t in self.dSources])
        
        taint_ctree = None
        if(len(self.cSources)>0):        
            taint_ctree = "\n{C}".join([("\t" * level + t.taint_tree(level+1)) for t in self.cSources])
        
        if(taint_dtree is None):
            return taintStr
        elif(taint_ctree is None):
            return "".join(["%s<-%s" % (taintStr,self.creatorInstAmenic), "\n", taint_dtree])
        elif(taint_dtree!=None and taint_ctree!=None):
            return "".join(["%s<-%s" % (taintStr,self.creatorInstAmenic), "\n", taint_dtree,"\n",taint_ctree])

    def taint_simple(self):
        taintStr ="[%s]" %(self.tuid)
        
        if(self.taintType == REGISTER_TAINT):
            taintStr =taintStr+"reg_"
        elif(self.taintType == MEMORY_TAINT):
            taintStr =taintStr+"mem_"
        elif(self.taintType == INPUT_TAINT):
            taintStr =taintStr+"in_"                             
        else:
            taintStr =taintStr+"bc_"
            
        if isinstance(self.taintAddress, int):
            taintStr = taintStr+hex(self.taintAddress)+"["+hex(self.creatorSequence)+":"+hex(self.creatorThread)+"]"
        else:
            taintStr = taintStr+str(self.taintAddress)+"["+hex(self.creatorSequence)+":"+hex(self.creatorThread)+"]"
            
        if(self.terminatorInstruction!=None and self.terminatorThread !=None):
            taintStr = taintStr+"["+hex(self.terminatorInstruction)+":"+hex(self.terminatorThread)+"]"
        
        if(self.bDirectInput==True):
            taintStr = taintStr + "<-"+hex(self.InputFunctionCallerAddress)+":"+str(self.creatorInstAmenic)
            return taintStr
        
        taintStr = "%s<-%s" % (taintStr,self.creatorInstAmenic)

        if(len(self.dSources)>0):                
            sDSrc = ""
            for dSrc in self.dSources:
                sDSrc = sDSrc + str(dSrc.tuid) +" "               
            taintStr = taintStr +"{D}" + sDSrc

        if(len(self.cSources)>0):                
            sCSrc = ""
            for cSrc in self.cSources:
                sCSrc = sCSrc + str(cSrc.tuid) +" "               
            taintStr = taintStr +"{C}" + sCSrc
                
        return taintStr
    
    def dumpTaintTree(self,output_fd):
        taintids=set()
        taintids.add(self.tuid)
        
        while len(taintids)!=0:
            tid = taintids.pop()
            taint = Taint.uid2Taint[tid]
            for dSrc in taint.dSources:
                taintids.add(dSrc.tuid)
            for cSrc in taint.cSources:
                taintids.add(cSrc.tuid)
            if(tid not in Taint.visited):
                output_fd.write("%s\n" %taint.taint_simple())
                Taint.visited.add(tid)

