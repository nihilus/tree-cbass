try:
  import networkx as nx
  NetworkX = True
except:
  print "[debug] No Networkx library support"
  pass
from PySide import QtGui, QtCore
from PySide.QtGui import QIcon

import os
import idaapi

class AnalyzerWidget(QtGui.QMainWindow):
    """
    This widget is the front-end for the trace generations.
    """
    def __init__(self,parent):
        QtGui.QMainWindow.__init__(self)
        print "[|] loading AnalyzerWidget"
        self.parent = parent
        self.name = "Taint Analysis"
        path = os.path.join(self.parent.iconPath, "trace.png")
        self.icon = QIcon(path)
        
        #References to qt-specific modules
        self.QtGui = QtGui
        self.QtCore = QtCore
        self.central_widget = self.QtGui.QWidget()
        self.setCentralWidget(self.central_widget)
        self._defineAnalyzeTypes()
        self._definePropEnum()
        self.t_graph = nx.MultiDiGraph()
        self.ExTraces = idaapi.netnode("$ ExTraces", 0, False) #Get the execution trace id
        self.trace_data = self.ExTraces.getblob(0, 'A') #Get the execution trace data, use str(data) to convert to data to a str
        self._createGui()
        
    def _createGui(self):
        """
        Create the main GUI with its components
        """
        self._createToolbar()
        
        self._createImageTable()
        self._createSourceTable()
        self._createTraceTable2()
        self._initializeImagesTable()
        self._initializeSourcesTable()
        #Layout information
        trace_layout = QtGui.QVBoxLayout()
        
        taint_info_widget = QtGui.QWidget()
        taint_info_layout = QtGui.QHBoxLayout()
        self.propPolicy = QtGui.QGroupBox("Taint Propagation Policy")
        self.analyzeTypeGroup = QtGui.QGroupBox("Instruction Set Architecture")
        vbox = QtGui.QVBoxLayout()
        
        self.radioGroup = QtGui.QButtonGroup()
        self.radioGroup.setExclusive(True)
        bIsFirst = True
        for i,row in enumerate(self.analyze_types):
            radio = QtGui.QRadioButton(row)
            self.radioGroup.addButton(radio, i)
            if bIsFirst:
                radio.setChecked(True)
                bIsFirst = False
            else:
                radio.setEnabled(False)
            vbox.addWidget(radio)
        
        vbox2 = QtGui.QVBoxLayout()
        self.radioGroup2 = QtGui.QButtonGroup()
        self.radioGroup2.setExclusive(True)
        bIsFirst = True
        for i,row in enumerate(self.taint_prop):
            radio = QtGui.QRadioButton(row)
            self.radioGroup2.addButton(radio, i)
            if bIsFirst:
                radio.setChecked(True)
                bIsFirst = False
            #Disable Address Propagation
            #06/27/13
            if i == 3:
                radio.setEnabled(False)
            vbox2.addWidget(radio)
            
        self.analyzeTypeGroup.setLayout(vbox)
        self.propPolicy.setLayout(vbox2)
        #self.sink_taint_only_cb.stateChanged.connect(self.populateVMTable)
        taint_info_layout.addWidget(self.propPolicy)
        taint_info_layout.addWidget(self.analyzeTypeGroup)
        
        self.indexFileGroupBox = QtGui.QGroupBox("Misc")
        vbox2 = QtGui.QVBoxLayout()
        self.pin_trace_cb = QtGui.QCheckBox("PIN")     
        self.pin_trace_cb.setEnabled(False)
        vbox2.addWidget(self.pin_trace_cb)
        self.verbose_trace_cb = QtGui.QCheckBox("Verbose")
        vbox2.addWidget(self.verbose_trace_cb)
        #vbox2.addWidget(self.indexFileIn)
        #vbox2.addWidget(self.indexFileStr)
        self.indexFileGroupBox.setLayout(vbox2)
        taint_info_layout.addWidget(self.indexFileGroupBox)
        
        taint_info_widget.setLayout(taint_info_layout)
        
        upper_table_widget = QtGui.QWidget()
        upper_table_layout = QtGui.QVBoxLayout()
        upper_table_layout.addWidget(taint_info_widget)
        #upper_table_layout.addWidget(self.trace_table)
        upper_table_widget.setLayout(upper_table_layout)
        
        details_widget = QtGui.QWidget()
        details_layout = QtGui.QHBoxLayout()
        self.imagesBox = QtGui.QGroupBox("Image Load Table")
        imBox = QtGui.QVBoxLayout()
        imBox.addWidget(self.images_table)
        self.imagesBox.setLayout(imBox)
        details_layout.addWidget(self.imagesBox)
        self.sourcesBox = QtGui.QGroupBox("Taint Source Table")
        soBox = QtGui.QVBoxLayout()
        soBox.addWidget(self.sources_table)
        self.sourcesBox.setLayout(soBox)
        details_layout.addWidget(self.sourcesBox)
        self.taintOutBox = QtGui.QGroupBox("Taint Graph Output")
        toBox = QtGui.QVBoxLayout()
        toBox.addWidget(self.trace_table2)
        self.taintOutBox.setLayout(toBox)
        details_layout.addWidget(self.taintOutBox)
        
        
        details_widget.setLayout(details_layout)
        
        lower_tables_widget = QtGui.QWidget()
        lower_tables_layout = QtGui.QVBoxLayout()
        lower_tables_layout.addWidget(details_widget)
        lower_tables_widget.setLayout(lower_tables_layout)
        
        splitter = self.QtGui.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = QtGui.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(upper_table_widget)
        splitter.addWidget(lower_tables_widget)
        trace_layout.addWidget(splitter)
        
        self.central_widget.setLayout(trace_layout)
        self.populateTraceTables()
        
    def _defineAnalyzeTypes(self):
        """
        Generate the analyze types list
        """
        self.analyze_types = []
        self.analyze_types.append("x86")
        self.analyze_types.append("x86_64")
        self.analyze_types.append("ARM")
        self.analyze_types.append("PPC")
        self.analyze_types.append("MIPS")
        
    def _definePropEnum(self):
        """
        Generate the taint propagation policies
        """
        self.taint_prop = []
        #self.taint_prop.append("TAINT_NOPE")
        self.taint_prop.append("TAINT_DATA")
        self.taint_prop.append("TAINT_BRANCH")
        self.taint_prop.append("TAINT_COUNTER")
        self.taint_prop.append("TAINT_ADDRESS")
        #self.taint_prop.append("TAINT_LAST")
        
    def _createToolbar(self):
        """
        Create the toolbar
        """
        self._createAnalyzeAction()
        
        self.toolbar = self.addToolBar('Trace Generation Toolbar')
        self.toolbar.addAction(self.generateAnalyzeAction)
        
    def _createAnalyzeAction(self):
        """
        Create that action that performs the trace
        """
        path = os.path.join(self.parent.iconPath,"trace.png")
        self.generateAnalyzeAction = QtGui.QAction(QIcon(path), "Start taint analysis", self)
        self.generateAnalyzeAction.triggered.connect(self.onStartAnalyzeButtonClicked)
        
    def updateTaintsLabel(self,n1, n2):
        """
        Action for updating the TaintsLabel
        """
        self.taint_nodes_label.setText("Taint Nodes(%d/%d)" %
            (n1, n2))
            
    def generateInternalGraph(self):
        """
        Action for refreshing the window data by checking each process
        """
        import re
        if hasattr(self, 'f_taint'):
            #import taint file
            taint_in = open(self.f_taint, 'r')
            #
            # TAINT_BRANCH taint nodes do not indicate explicit children but
            # have tab indicating depth and children
            #
            if self.radioGroup2.checkedButton().text() == "TAINT_BRANCH":
                self.cur_depth = 0
                self.cur_taint_node = None
                for line in taint_in:
                    line = line.rstrip('\n')
                    depth = re.match('\t*', line).group(0).count('\t')
                    if (depth == 0):
                        self.insert_node_br(line, 0)
                    else:
                        nodedata = line[depth:]
                        self.insert_node_br(nodedata, depth)
            else:
                for line in taint_in:
                    self.insert_node(line.rstrip('\n'))
                self.t_graph.reverse(copy=False)
            
    def insert_node_br(self, s, depth):
        from ..core.structures.Parse.TaintNode import TaintNode
        try:
            uuid = self.extract_uuid(s)
        except AttributeError:
            return
        if uuid is None:
            return
        if self.t_graph.has_node(uuid):
            return
        tempNode = TaintNode()
        tempNode.depth = depth
        tempNode.ExtractData(s)
        if tempNode.typ is None:
            return
        self.t_graph.add_node(uuid, inode = tempNode)
        if depth == 0:
            self.cur_taint_node = tempNode
            self.cur_depth = depth
            return
        elif (depth > self.cur_depth):
            if self.cur_taint_node.edgeann is not None:
                self.t_graph.add_edge(str(self.cur_taint_node), str(tempNode), anno=self.cur_taint_node.edgeann)
            else:
                self.t_graph.add_edge(str(self.cur_taint_node), str(tempNode))
            self.cur_depth = depth
        elif(depth == self.cur_depth):
            if self.cur_taint_node.edgeann is not None:
                self.t_graph.add_edge(self.t_graph.predecessors(str(self.cur_taint_node))[0], tempNode, anno=self.t_graph.predecessors(str(self.cur_taint_node))[0].edgeann)
            else:
                self.t_graph.add_edge(self.t_graph.predecessors(str(self.cur_taint_node))[0], tempNode)
        #Have to cover for the case where node is root of tree
        else:
            print depth
            print self.cur_taint_node
            print s
            print self.t_graph.predecessors(str(self.cur_taint_node))
            parent = self.t_graph.predecessors(str(self.cur_taint_node))[0]
            for i in range(0, self.cur_depth - depth):
                parent = self.t_graph.predecessors(str(parent))[0]
            if parent.edgeann is not None:
                self.t_graph.add_edge(str(parent), str(tempNode), anno=parent.edgeann)
            else:
                self.t_graph.add_edge(str(parent), str(tempNode))
            self.cur_depth = depth
        self.cur_taint_node = tempNode
            
    def insert_node(self, s):
        from ..core.structures.Parse.TaintNode import TaintNode
        tempNode = None
        try:
            uuid = self.extract_uuid(s)
        except AttributeError:
            return
        if self.t_graph.has_node(uuid):
            tempNode = self.t_graph.node[uuid]['inode']
            tempNode.ExtractData(s)
        else:
            tempNode = TaintNode()
            tempNode.ExtractData(s)
            self.t_graph.add_node(uuid, inode = tempNode)
        self.child_edges(tempNode)

    def child_edges(self, node):
        from ..core.structures.Parse.TaintNode import TaintNode
        for attr, value in node.__dict__.iteritems():
            if(attr.startswith('child')):
                x = getattr(node, attr)
                if x is not None:
                    for child in x.split():
                        if self.t_graph.has_node(child):
                            self.t_graph.add_edge(str(node), child, anno=node.edgeann, edgetype=attr.split('_')[1])
                            tempNode = self.t_graph.node[child]['inode']
                            tempNode.SetNodeAttr(attr.split('_')[1])
                        else:
                            newNode = TaintNode(child)
                            newNode.SetNodeAttr(attr.split('_')[1])
                            self.t_graph.add_node(child, inode = newNode)
                            self.t_graph.add_edge(str(node), child, anno=node.edgeann, edgetype=attr.split('_')[1])
    def extract_uuid(self, s):
        import re
        pattern = re.compile(r"""
                            \[(?P<uuid>\d+)\].*
                            """, re.VERBOSE)
        m = pattern.search(s)
        return str(m.group('uuid'))
        
    def onStartAnalyzeButtonClicked(self):
        """
        Action for calling the analyzer functionality 
        """
        import sys
        import os
        import idc
        import logging
        import struct
        from ..core.structures.Analyzer import TaintTracker
        from ..core.structures.Analyzer.TraceParser import IDBTraceReader        
        from ..core.structures.Analyzer.TraceParser import Invalid, LoadImage, UnloadImage, Input, ReadMemory, WriteMemory, Execution, Snapshot, eXception
        from ..core.structures.Analyzer.TaintTracker import TaintTracker,TAINT_NOPE,TAINT_ADDRESS,TAINT_BRANCH,TAINT_COUNTER,TAINT_DATA,IDA, PIN 
        from ..core.structures.Analyzer.x86Decoder import WINDOWS, LINUX
        from ..core.structures.Analyzer.TaintMark import TaintMarker
        from ..core.structures.Analyzer.TaintChecker import TaintChecker

        self.trace_fname = idc.GetInputFile()
        print ("IDB file name = %s") %(self.trace_fname)
        log = logging.getLogger('CIDATA')
        
        if self.verbose_trace_cb.isChecked():
            logging.basicConfig(filename="debug.log",level=logging.DEBUG)
        else:
            logging.basicConfig(filename="warning.log",level=logging.INFO)

        if self.verbose_trace_cb.isChecked():
          print ("Host System=%s" %sys.platform)

        hostOS = None	
        if(sys.platform == 'win32'):
            hostOS = WINDOWS
        elif (sys.platform == 'linux2'):
            hostOS = LINUX
        else:
            print ("Platform Not Implemented!")
            return

        processBits = 32
        #32Bit Check
        if(sys.maxsize > 2**32):
            processBits = 64
        targetBits = 32
        if (self.radioGroup.checkedButton().text() == "X86"):
            targetBits=32
        elif(self.radioGroup.checkedButton().text() == "X64"):
            targetBits=64
        
        TP = None #Taint Propogator
        TR = None # Trace Reader
        TM = None # Taint Marker
        TC = None #Taint Checker

        #Need to get the setting from GUI, default taint policy is TAINT_DATA:
        #taintPolicy = CIDTaintProp.TAINT_BRANCH # Used to test condOV;     
        taintPolicy = getattr(TaintTracker, self.radioGroup2.checkedButton().text(), "TAINT_DATA")
        #taint graph name begins with A(ddress), B(ranch), C(Counter) or D(ata) depending on policy
        #without extension
        idb_filename = os.path.basename(self.trace_fname).split(".")[0]+".txt"
        fTaint = "TaintGraph_"+idb_filename
        print ("Taint file name = %s") %(fTaint)
        if (taintPolicy == TAINT_BRANCH):
            fTaint = "BTaintGraph_"+idb_filename
        elif (taintPolicy == TAINT_DATA):
            fTaint = "DTaintGraph_"+idb_filename
        elif (taintPolicy == TAINT_COUNTER):
            fTaint = "CTaintGraph_"+idb_filename
        elif (taintPolicy == TAINT_ADDRESS):
            fTaint = "ATaintGraph_"+idb_filename
        out_fd = open(fTaint, 'w')
        
        TP = TaintTracker(hostOS, processBits, targetBits, out_fd,TAINT_DATA, IDA)	
        if (self.trace_data is not None):
            TR = IDBTraceReader(str(self.trace_data))
        else:
            print("No Trace found!")
            
        if TR is None:
            log.error("Failed to open trace. Exit")
            self.trace_table2.append("Failed to open trace.")
            return
        out_str = "Processing trace file %s..." %(self.trace_fname)
        self.trace_table2.append(out_str)

        TM = TaintMarker(TP)
        TC = TaintChecker(TP)
            
        if TP is None:
            log.error("Failed to create Taint Propogator. Exit")
            return

        if TM is None:
            log.error("Failed to create Taint Marker. Exit")
            return
        if TC is None:
            log.error("Failed to create Taint Checker. Exit")
            return
          
        tRecord = TR.getNext()
        bEnd = False
        tNextRecord = None
        strTaint = ""
        while tRecord!=None:
            tNextRecord = TR.getNext()
            recordType = tRecord.getRecordType()
            if (recordType == LoadImage):
                if (self.verbose_trace_cb.isChecked()):
                    print("ImageName=%s, LoadAddr = %x, Size=%x" %(tRecord.ImageName, tRecord.LoadAddress, tRecord.ImageSize))
                    out_str = "ImageName=%s, LoadAddr = %x, Size=%x" %(tRecord.ImageName, tRecord.LoadAddress, tRecord.ImageSize)
                    self.trace_table2.append(out_str)                     
            elif (recordType == Input):
                TM.SetInputTaint(tRecord)
                if(self.verbose_trace_cb.isChecked()):
                    print("InputAddr = %x, InputSize =%x" %(tRecord.currentInputAddr, tRecord.currentInputSize))
                    out_str = "InputAddr = %x, InputSize =%x" %(tRecord.currentInputAddr, tRecord.currentInputSize)
                    self.trace_table2.append(out_str)
            elif(recordType == Execution):
                if(tNextRecord.getRecordType() == eXception):
                    if(tNextRecord.currentExceptionCode ==0): # termination
                        if (taintPolicy == TAINT_BRANCH):
                          print("Path Condition\n")
                          strTaint = TC.DisplayPCs()
                        else:
                          strTaint = TC.DumpLiveTaints()	
                    else:
                        strTaint = TC.DumpFaultCause(tNextRecord, tRecord, self.verbose_trace_cb.isChecked())
                        if self.verbose_trace_cb.isChecked():
                          print "Exception! Get out of the loop!"
                        bEnd = True
                        break        					
                elif(TP.Propagator(tRecord)==1):
                    #bEnd = True
                    if(self.verbose_trace_cb.isChecked()):
                      print "Tainted Security Warning!"
                    #break
            else:
                print "Type not supported:%d" %recordType

            if (bEnd == True):
                tRecord = None
            else:
                tRecord = tNextRecord 				

        out_fd.close()
        
        text = strTaint
        self.f_taint = fTaint # TODO: enhance later, not to read from file
        self.trace_table2.setText(text)
        log.info("TREE Taint Analysis Finished")
        if self.verbose_trace_cb.isChecked():
          for x, y, d in self.t_graph.edges(data=True):
              print x
              print y
              print d
        self.generateInternalGraph()
        self.extendTaints()
        self.parent.setTabFocus("Visualizer")
        self.parent.passTaintGraph(self.t_graph, "Visualizer", self.radioGroup2.checkedButton().text())
            
    def populateTraceTables(self):
        """
        Populate the taints table
        For no uneditable
        """
        from ..core.structures.Analyzer.TraceParser import IDBTraceReader        
        from ..core.structures.Analyzer.TraceParser import Invalid, LoadImage, UnloadImage, Input, ReadMemory, WriteMemory, Execution, Snapshot, eXception
        self.node_ea = dict()
        self.node_lib = dict()
        TR = None

        if hasattr(self, "trace_data"):
            TR = IDBTraceReader(str(self.trace_data))
        else:
            return
        self.node_ea = dict()
        self.node_lib = dict()
        if self.verbose_trace_cb.isChecked():
          print "[debug] trace imported into dictionary"
        
        TR.reSet()
        tRecord = TR.getNext()
        while tRecord!=None:
            recordType = tRecord.getRecordType()
            if (recordType == LoadImage):
                imageName = None
                imageName = tRecord.ImageName[0] 
                self.node_lib[imageName] = str(tRecord.LoadAddress) + " " + str(tRecord.ImageSize)
                self.images_table.insertRow(self.images_table.rowCount())
                for column, column_name in enumerate(self.images_header_labels):
                    #Name
                    if column == 0: 
                        tmp_item = self.QtGui.QTableWidgetItem(str(tRecord.ImageName))
                    #Address
                    elif column == 1:
                        tmp_item = self.QtGui.QTableWidgetItem(str(hex(tRecord.LoadAddress)))
                    #Size
                    elif column == 2:
                        tmp_item = self.QtGui.QTableWidgetItem(str(hex(tRecord.ImageSize)))
                    tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                    self.images_table.setItem(self.images_table.rowCount()-1, column, tmp_item)                  
            elif (recordType == Input):
                self.sources_table.insertRow(self.sources_table.rowCount())
                for column, column_name in enumerate(self.sources_header_labels):
                    #currentInputAddr
                    if column == 0:
                        tmp_item = self.QtGui.QTableWidgetItem(str(hex(tRecord.currentInputAddr)))
                    #currentInputSize
                    elif column == 1:
                        tmp_item = self.QtGui.QTableWidgetItem(str(tRecord.currentInputSize))
                    #inputBytes
                    elif column == 2:
                        tmp_item = self.QtGui.QTableWidgetItem(str(tRecord.inputBytes))
                    tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                    self.sources_table.setItem(self.sources_table.rowCount()-1, column, tmp_item)
            elif(recordType==Execution):
                self.node_ea[hex(tRecord.currentInstSeq)] = tRecord.currentInstruction
            tRecord = TR.getNext()
        self.images_table.resizeColumnsToContents()
        self.sources_table.resizeColumnsToContents()
        self.images_table.selectRow(0)
        self.sources_table.selectRow(0)
        self.images_table.horizontalHeader().setResizeMode(self.QtGui.QHeaderView.Stretch)
        #self.sources_table.horizontalHeader().setResizeMode(self.QtGui.QHeaderView.Stretch)        
            
    def extendTaints(self):
        """
        Method to extend taint information with trace. Library context added to taint nodes from trace
        """
        for node in self.t_graph.nodes(data=True):
            ind = node[1]['inode'].startind.split(':')[0]
            if(self.pin_trace_cb.isChecked()):
                ind = int(ind, 0)
            addr = None
            try:
                addr = self.node_ea[ind]
            except KeyError:
                addr = None
            if addr is None:
                continue
            node[1]['inode'].setEA(addr)
            if node[1]['inode'].ea:
                for key in self.node_lib.keys():
                    base_addr = int(self.node_lib[key].split(' ')[0])
                    end_addr = base_addr + int(self.node_lib[key].split(' ')[1])
                    if node[1]['inode'].ea >= base_addr and node[1]['inode'].ea < end_addr:
                        if self.verbose_trace_cb.isChecked():
                          print "Found library: %s" % key
                        node[1]['inode'].setLib(key)
                        break
            
    def onImportTraceButtonClicked(self):
        """ 
        Action for importing an XML file containing VM information
        """
        #from dispatcher.core.structures.Parse import TrNode
        fname, _ = self.QtGui.QFileDialog.getOpenFileName(self, 'Import Trace')
        self.trace_fname = fname
        #self.populateTraceTable()
        
    def onTransferFromTraceWidget(self, fname):
        """ 
        Action continuation from trace generation
        """
        self.trace_fname = fname
    
    def onImportIndexButtonClicked(self):
        """
        Action for importing an XML file containing VM information
        """
        fname, _ = self.QtGui.QFileDialog.getOpenFileName(self, 'Import Index')
        self.index_fname = fname
        self.indexFileStr.setText(fname)
        
    def _createImageTable(self):
        """
        Create the bottom left table
        """
        self.images_table = QtGui.QTableWidget()
        #self.images_table.doubleClicked.connect(self._onDetailsDoubleClicked)
        
    def _createSourceTable(self):
        """
        Create the bottom left table
        """
        self.sources_table = QtGui.QTableWidget()
        #self.images_table.doubleClicked.connect(self._onDetailsDoubleClicked)
        
    def _initializeImagesTable(self):
        """
        Populate the VM table with information about the virtual machines
        """
        #If no config then connect to virtualbox in config
        self.images_table.setSortingEnabled(False)
        self.images_header_labels = ["Name", "Address", "Size"]
        self.images_table.clear()
        self.images_table.setColumnCount(len(self.images_header_labels))
        self.images_table.setHorizontalHeaderLabels(self.images_header_labels)
        self.images_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.images_table.resizeColumnsToContents()
        self.images_table.verticalHeader().setVisible(False)
        self.images_table.setSortingEnabled(True)
        
    def _initializeSourcesTable(self):
        """
        Populate the VM table with information about the virtual machines
        """
        #If no config then connect to virtualbox in config
        self.sources_table.setSortingEnabled(False)
        self.sources_header_labels = ["Input Address", "Size", "Input Bytes"]
        self.sources_table.clear()
        self.sources_table.setColumnCount(len(self.sources_header_labels))
        self.sources_table.setHorizontalHeaderLabels(self.sources_header_labels)
        self.sources_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.sources_table.resizeColumnsToContents()
        self.sources_table.verticalHeader().setVisible(False)
        self.sources_table.setSortingEnabled(True)
    
    def _createTraceTable2(self):
        """
        Create the bottom right table
        """
        self.trace_table2 = QtGui.QTextEdit()
        #self.trace_table.doubleClicked.connect(self._onTraceDoubleClicked)
        
    def traceTableWriter(self, text):
        """
        Writer method to append text to the trace table
        """
        self.trace_table2.append(text)