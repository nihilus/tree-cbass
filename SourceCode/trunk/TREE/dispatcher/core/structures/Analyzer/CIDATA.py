'''

This is the main script for IR-based taint analysis and symbolic execution program. 
Inputs:
	-- Dynamic Trace File
	-- Database, module and table information to connect to static artifacts generated from disassembly and static analysis 
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
import CIDTaintProp
from CIDParser import CIDATraceReader, CIDATextTraceReader, CIDAPinTraceReader

from CIDParser import Invalid, LoadImage,UnloadImage,Input,ReadMemory,WriteMemory,Execution, Snapshot, eXception
from CIDTaintProp import TaintPropagator

X86 = 1
X64 = 2
ARM = 3
PPC = 4
MIPS = 5

 
def main(args):
	print ("CBASS Taint Analysis Program for IDA-based Trace")
	parser = OptionParser()
	parser.add_option("-a", "--arch", dest="arch",default="X86",
					  help="The instruction set")
	parser.add_option("-p", "--pintrace", dest="pin_trace",default=False,action="store_true",
					  help="Read trace from PIN format")
	parser.add_option("-t", "--trace", dest="trace_file",default="None",
                      help="The trace file to parse")
	parser.add_option("-i", "--index", dest="index_file",default="None",
                      help="The instruction index file")	
	parser.add_option("-v", "--verbose", dest="verbose", default=False, action="store_true",
                      help="Display detailed instruction simulation process ")

	(options, args) = parser.parse_args()
	log = logging.getLogger('CIDATA')
	
	if options.verbose:
		logging.basicConfig(filename="debug.log",level=logging.DEBUG)
	else:
		logging.basicConfig(filename="warning.log",level=logging.INFO)
	
	processBits = 32
	if(sys.maxsize > 2**32):
		processBits = 64

	targetBits = 32
	if(options.arch == "X86"):
		targetBits = 32
	elif(options.arch == "X64"):
		targetBits = 64
		
	if (options.pin_trace):
		#tr = CIDAPinTraceReader(options.trace_file,"inst_basicplus")
		#tr = CIDAPinTraceReader(options.trace_file,"inst_basic.txt")
		#tr = CIDAPinTraceReader(options.trace_file,"inst_792") #for WMF
		tr = CIDAPinTraceReader(options.trace_file,options.index_file)
		CIDTaintProp.traceType = CIDTaintProp.PIN
	else:
		tr = CIDATextTraceReader(options.trace_file)
		CIDTaintProp.traceType = CIDTaintProp.IDA
		
	if tr is None:
		log.error("Failed to open trace file. Exit")
		sys.exit(-1)
		
	print ("Processing trace file %s..." %(options.trace_file))
	fTaint = "TaintGraph_"+options.trace_file
	out_fd = open(fTaint, 'w')
    
	TP = TaintPropagator(processBits, targetBits, out_fd)	
	tRecord = tr.getNext()
	tLastRecord = None
	while tRecord!=None:
		recordType = tRecord.getRecordType()
		if (recordType == LoadImage):
			if options.verbose:
				print("ImageName=%s, LoadAddr = %x, Size =%x" %(tRecord.ImageName, tRecord.LoadAddress, tRecord.ImageSize))
		elif (recordType == Input):
			if options.verbose:
				print("InputAddr = %x, InputSize =%x" %(tRecord.currentInputAddr, tRecord.currentInputSize))
			TP.SetInputTaint(tRecord.currentInputAddr, tRecord.currentInputSize)
		elif (recordType == Execution):
			tLastRecord = tRecord
			#print("Propagating Execution: address = %x, size = %d, encoding =%s" %(tRecord.currentInstruction, tRecord.currentInstSize,tRecord.sEncoding))
			if(TP.Propagator(tRecord)==1):
				if options.verbose:
					print("Tainted Security Warning!")
		elif (recordType == eXception):
			#print("Exception address = %x, code =%x" %(tRecord.currentExceptionAddress, tRecord.currentExceptionCode))
			if(tLastRecord !=None):
				TP.DumpFaultCause(tRecord, options.verbose)
			break
		else:
			print("Type %d not supported:" %recordType)
		tRecord = tr.getNext()

	#TP.DumpLiveTaints()
	#TP.DumpLiveTaintsInOrder()
	out_fd.close()
	
	log.info("CIDATA exit")
	sys.exit()

if __name__ == "__main__":
	try:
		main(sys.argv)
	except KeyboardInterrupt:
		print ("User Interrupted")
