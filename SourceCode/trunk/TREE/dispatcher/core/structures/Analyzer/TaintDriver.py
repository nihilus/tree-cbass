'''

This is the main script for IR-based taint analysis and symbolic execution program. 
Inputs:
	-- Dynamic Trace File
	-- Static artifacts generated from IDA disassembly and static analysis 
 Output:
   -- Taint results along the path from the dynamic trace
   -- Constraints modeled after the input as free variables
   -- Monitor interesting taints, generate assertion and query a solver for satisfiability and assignments
    
 * @author Nathan Li
 * 
 */

'''
import sys
import os
from optparse import OptionParser
import logging
import struct
from TraceParser import TraceReader, IDATextTraceReader, PinTraceReader
from TraceParser import Invalid, LoadImage,UnloadImage,Input,ReadMemory,WriteMemory,Execution, Snapshot, eXception
from TaintTracker import TaintTracker, TAINT_ADDRESS, TAINT_BRANCH,TAINT_COUNTER,TAINT_DATA, IDA, PIN 
from x86Decoder import WINDOWS, LINUX
from TaintTracker import TaintTracker
from TaintMark import TaintMarker
from TaintChecker import TaintChecker

#instruction set enumeration
X86 = 1
X64 = 2
ARM = 3
PPC = 4
MIPS = 5

def main(args):
    print ("TREE Interactive Taint Analysis and Replayer")
    parser = OptionParser()
    parser.add_option("-a", "--arch", dest="arch",default="X86",
                     help="The instruction set")
    parser.add_option("-p", "--pintrace", dest="pin_trace",default=False,action="store_true",
                     help="Read trace from PIN format")
    parser.add_option("-t", "--trace", dest="trace_file",default="None",
                      help="The trace file to parse")
    parser.add_option("-s", "--start", dest="startSequence",default=0,
                      help="The point to start taint tracking")
    parser.add_option("-e", "--end", dest="endSequence",default=-1,
                      help="The point to end taint tracking")
    parser.add_option("-i", "--settaint", dest="taintSource",default="Input",
                      help="Initial taint source marking")    
    parser.add_option("-v", "--verbose", dest="verbose", default=False, action="store_true",
                      help="Display detailed instruction simulation process ")

    (options, args) = parser.parse_args()
    log = logging.getLogger('CIDATA')
    
    if options.verbose:
	os.remove("debug.log") #clean existing debug log
        logging.basicConfig(filename="debug.log",level=logging.DEBUG)	
    else:
	os.remove("warning.log") #clean existing debug log
        logging.basicConfig(filename="warning.log",level=logging.INFO)

    if options.verbose:
	print ("Host System=%s" %sys.platform)
	print ("Start Sequence = %d" %(int(options.startSequence)))
	if(options.endSequence !=-1):
	    print ("End Sequence = %d" %(int(options.endSequence)))
	else:
	    print ("No End!")
	
    hostOS = None	
    if(sys.platform == 'win32'):
        hostOS = WINDOWS
    elif (sys.platform == 'linux2'):
        hostOS = LINUX
    else:
        print ("Platform Not Implemented!")
        return
    #host process
    processBits = 32
    if(sys.maxsize > 2**32):
        processBits = 64

    #We only process x86 32-bit code at this time
    targetBits = 32
    if(options.arch == "X86"):
        targetBits = 32
    elif(options.arch == "X64"):
        targetBits = 64

    fTaint = "TaintGraph_"+options.trace_file
    out_fd = open(fTaint, 'w')
	
    TP = None #Taint Propogator
    TR = None # Trace Reader
    TM = None # Taint Marker
    TC = None #Taint Checker
    if (options.pin_trace):
	print("PIN TRACE")
	TP = TaintTracker(hostOS, processBits, targetBits, out_fd,TAINT_DATA, PIN)		
        TR = PinTraceReader(options.trace_file)
    else:
	TP = TaintTracker(hostOS, processBits, targetBits, out_fd,TAINT_DATA, IDA)	
        TR = IDATextTraceReader(options.trace_file)
    TM = TaintMarker(TP)
    TC = TaintChecker(TP)
    
    if TR is None:
        log.error("Failed to open trace file. Exit")
        sys.exit(-1)

    if TP is None:
        log.error("Failed to create taint tracker. Exit")
        sys.exit(-1)

    if TM is None:
        log.error("Failed to create taint marker. Exit")
        sys.exit(-1)

    if TC is None:
        log.error("Failed to create taint checker. Exit")
        sys.exit(-1)
    
    #Initial taint source marking
    if(options.taintSource.find("Input")==-1):
	TM.setInteractiveTaint(options.taintSource)
    #else assume taint source is set through Input event read from trace file
    
    print ("Processing trace file %s..." %(options.trace_file))
    
    tRecord = TR.getNext()
    bEnd = False
    tNextRecord = None
    while tRecord!=None:
        tNextRecord = TR.getNext()
        recordType = tRecord.getRecordType()
        if (recordType == LoadImage):
            if options.verbose:
                print("ImageName=%s, LoadAddr = %x, Size=%x" %(tRecord.ImageName, tRecord.LoadAddress, tRecord.ImageSize))
                out_str = "ImageName=%s, LoadAddr = %x, Size=%x" %(tRecord.ImageName, tRecord.LoadAddress, tRecord.ImageSize)
        elif (recordType == Input):
            TM.SetInputTaint(tRecord)
            if options.verbose:
                print("InputAddr = %x, InputSize =%x" %(tRecord.currentInputAddr, tRecord.currentInputSize))
                out_str = "InputAddr = %x, InputSize =%x" %(tRecord.currentInputAddr, tRecord.currentInputSize)
        elif(recordType == Execution):
            if(tNextRecord.getRecordType() == eXception):
                if(tNextRecord.currentExceptionCode ==0): # termination
                    TC.DumpLiveTaints()	
                else:
		    if(options.pin_trace):
			TC.DumpExceptionAnalysis(tNextRecord, tRecord, options.verbose)
		    else:
                        TC.DumpFaultCause(tNextRecord, tRecord, options.verbose)
                    print "Exception! Get out of the loop!"
                    bEnd = True
                    break        					
            elif((tRecord.currentInstSeq>= options.startSequence) and (options.endSequence==-1 or (tRecord.currentInstSeq <= options.endSequence))):
                if (TP.Propagator(tRecord)==1):
		    bEnd = True
		    if options.verbose:
		        print "Tainted Security Warning!"
		    break
        else:
            print "Type %d not supported:%d" %recordType

        if (bEnd == True):
            tRecord = None
        else:
            tRecord = tNextRecord
    out_fd.close()
    log.info("CIDATA exit")
    sys.exit()

if __name__ == "__main__":
	try:
		main(sys.argv)
	except KeyboardInterrupt:
		print ("User Interrupted")
