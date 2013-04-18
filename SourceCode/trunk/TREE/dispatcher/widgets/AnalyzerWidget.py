try:
  import networkx as nx
  NetworkX = True
except:
  print "[debug] No Networkx library support"
  pass
from PySide import QtGui, QtCore
from PySide.QtGui import QIcon

class AnalyzerWidget(QtGui.QMainWindow):
    """
    This widget is the front-end for the trace generations.
    """
    def __init__(self,parent):
        QtGui.QMainWindow.__init__(self)
        print "[|] loading AnalyzerWidget"
        # Access to shared modules
        self.parent = parent
        self.name = "Taint Analysis"
        self.icon = QIcon(self.parent.iconPath + "trace.png")
        
        #References to qt-specific modules
        self.QtGui = QtGui
        self.QtCore = QtCore
        #self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self.central_widget = self.QtGui.QWidget()
        self.setCentralWidget(self.central_widget)
        self._defineAnalyzeTypes()
        self._definePropEnum()
        self._createGui()
        self.t_graph = nx.MultiDiGraph()
        
    def _createGui(self):
        """
        Create the main GUI with its components
        """
        # Create buttons
        self.trace_label = QtGui.QLabel("Trace Nodes (0/0)")
        self.taint_nodes_label = QtGui.QLabel("Taint Nodes(0/0)")
        
        self._createToolbar()
        
        self._createTraceTable()
        self._createTaintsTable() #create detailst able
        self._createTraceTable2()
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
            vbox.addWidget(radio)
        
        vbox2 = QtGui.QVBoxLayout()
        self.radioGroup2 = QtGui.QButtonGroup()
        self.radioGroup.setExclusive(True)
        bIsFirst = True
        for i,row in enumerate(self.taint_prop):
            radio = QtGui.QRadioButton(row)
            self.radioGroup2.addButton(radio, i)
            if bIsFirst:
                radio.setChecked(True)
                bIsFirst = False
            vbox2.addWidget(radio)
            
        
        self.analyzeTypeGroup.setLayout(vbox)
        self.propPolicy.setLayout(vbox2)
        #self.sink_taint_only_cb.stateChanged.connect(self.populateVMTable)
        taint_info_layout.addWidget(self.trace_label)
        taint_info_layout.addWidget(self.propPolicy)
        taint_info_layout.addWidget(self.analyzeTypeGroup)
        
        self.indexFileGroupBox = QtGui.QGroupBox("Misc")
        vbox2 = QtGui.QVBoxLayout()
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
        details_layout.addWidget(self.taints_table)
        details_layout.addWidget(self.trace_table2)
        details_widget.setLayout(details_layout)
        
        lower_tables_widget = QtGui.QWidget()
        lower_tables_layout = QtGui.QVBoxLayout()
        lower_tables_layout.addWidget(self.taint_nodes_label)
        lower_tables_layout.addWidget(details_widget)
        lower_tables_widget.setLayout(lower_tables_layout)
        
        splitter = self.QtGui.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = QtGui.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(upper_table_widget)
        splitter.addWidget(lower_tables_widget)
        trace_layout.addWidget(splitter)
        
        self.central_widget.setLayout(trace_layout)
        self.populateTraceTable()
        #self.populateTaintsTable()
        #self.populateVMTable()
        #self.updateVMLabel()
        
        
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
        self.taint_prop.append("TAINT_ADDRESS")
        self.taint_prop.append("TAINT_BRANCH")
        self.taint_prop.append("TAINT_COUNTER")
        #self.taint_prop.append("TAINT_LAST")
        
    def _createToolbar(self):
        """
        Create the toolbar
        """
        self._createRefreshAction()
        self._createImportTraceAction()
        self._createImportIndexAction()
        self._createAnalyzeAction()
        
        self.toolbar = self.addToolBar('Trace Generation Toolbar')
        self.toolbar.addAction(self.refreshAction)
        self.toolbar.addAction(self.importTraceAction)
        self.toolbar.addAction(self.generateAnalyzeAction)
        
    def _createRefreshAction(self):
        """
        Create the refresh action for the oolbar. triggers a scan of virtualmachines and updates the GUI.
        """
        self.refreshAction = QtGui.QAction(QIcon(self.parent.iconPath + "refresh.png"), "Refresh the " \
            + "taint data", self)
        self.refreshAction.triggered.connect(self._onRefreshButtonClicked)
        
    def _createAnalyzeAction(self):
        """
        Create that action that performs the trace
        """
        self.generateAnalyzeAction = QtGui.QAction(QIcon(self.parent.iconPath + \
            "trace.png"), "Generate the taint graph", self)
        self.generateAnalyzeAction.triggered.connect(self.onStartAnalyzeButtonClicked)
        
    def _createImportTraceAction(self):
        """
        Create the import trace action
        """
        self.importTraceAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "import.png"),
            "Import the trace file", self)
        self.importTraceAction.triggered.connect(self.onImportTraceButtonClicked)
        
    def _createImportIndexAction(self):
        """
        Create an import button that calls QFileDialog
        """
        self.pin_trace_cb = QtGui.QCheckBox("PIN Trace")
        self.indexFileIn = QtGui.QPushButton()
        #self.indexFileIn.setGeometry(QtCore.QRect(0,0,25,19))
        self.indexFileIn.setToolTip("Import index file for PIN.")
        self.indexFileIn.setText("Import Index File")
        self.indexFileStr = QtGui.QLabel("Import Index File")
        self.indexFileIn.clicked.connect(self.onImportIndexButtonClicked)
        
    def _createTraceTable(self):
        """
        Create the top table used for showing all
        """
        self.trace_table = QtGui.QTableWidget()
        self.trace_table.clicked.connect(self.onTraceClicked)
        #self.trace_table.doubleClicked.connect(self.onProcessDoubleClicked)
        
    def populateTraceTable(self):
        """
        Populate the VM table with information about the virtual machines
        """
        #If no config then connect to virtualbox in config
        self.trace_table.setSortingEnabled(False)
        self.trace_header_labels = ["Node", "Type", "EA", "Index1", "Index2", "Instr", "Anno"]
        self.trace_table.clear()
        self.trace_table.setColumnCount(len(self.trace_header_labels))
        self.trace_table.setHorizontalHeaderLabels(self.trace_header_labels)
        if hasattr(self, 'f_taint'):
            processes = self.t_config.root.findall('process')
            self.trace_table.setRowCount(len(processes))
            for row, node in enumerate(processes):
                for column, column_name in enumerate(self.process_header_labels):
                    ##@todo Determine if VM and if online
                    if column == 0:
                        tmp_item = self.QtGui.QTableWidgetItem(node.find('input').find('remote').text)
                    elif column == 1:
                        tmp_item = self.QtGui.QTableWidgetItem(node.attrib['name'])
                    elif column == 2:
                        osarch = node.find('platform').find('OS').text + ' ' + node.find('platform').find('Arch').text
                        tmp_item = self.QtGui.QTableWidgetItem(osarch)
                    tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                    self.trace_table.setItem(row, column, tmp_item)
                self.trace_table.resizeRowToContents(row)
            self.trace_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.trace_table.resizeColumnsToContents()
            self.trace_table.setSortingEnabled(True)
        else:
            self.trace_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.trace_table.resizeColumnsToContents()
            self.trace_table.setSortingEnabled(True)
            
    def populateTaintsTable(self):
        """
        Populate the taints table
        For no uneditable
        @Todo:
            Make editable and have changes pushed out to file
        """
        self.taints_table.setSortingEnabled(False)
        if self.radioGroup2.checkedButton().text() == "TAINT_BRANCH":
            self.taints_header_labels = ["UUID", "Type", "Name", "StartInd", "EndInd", "Edge Anno"]
        else:
            self.taints_header_labels = ["UUID", "Type", "Name", "StartInd", "EndInd", "Edge Anno", "Child C", "Child D"]
        self.taints_table.clear()
        self.taints_table.setColumnCount(len(self.taints_header_labels))
        self.taints_table.setHorizontalHeaderLabels(self.taints_header_labels)
        self.taints_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.taints_table.resizeColumnsToContents()
        self.taints_table.setSortingEnabled(True)
        
    def _onRefreshButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        
    def updateTaintsLabel(self,n1, n2):
        """
        Action for updating the TaintsLabel
        """
        self.taint_nodes_label.setText("Taint Nodes(%d/%d)" %
            (n1, n2))
            
    def populateTaintsOnGen(self):
        """
        Action for refreshing the window data by checking each process
        @TODO redo this entire method 3/27/13
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
            self.taints_table.setRowCount(len(self.t_graph))
            self.updateTaintsLabel(len(self.t_graph), len(self.t_graph))
            if self.radioGroup2.checkedButton().text() == "TAINT_BRANCH":
                for row, ynode in enumerate(self.t_graph.nodes(data=True)):
                    for column, column_name in enumerate(self.taints_header_labels):
                        #Temporary fix until we can figure out why networkx is adding null nodes
                        #try:
                        #    print ynode[1]['inode'].uuid
                        #except AttributeError:
                        #    break
                        if column == 0:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].uuid)
                        elif column == 1:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].typ)
                        elif column == 2:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].name)
                        elif column == 3:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].startind)
                        elif column == 4:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].endind)
                        elif column == 5:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].edgeann)
                        tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                        self.taints_table.setItem(row, column, tmp_item)
                    self.taints_table.resizeRowToContents(row)
            else:
                for row, ynode in enumerate(self.t_graph.nodes(data=True)):
                    for column, column_name in enumerate(self.taints_header_labels):
                        ##@self.process_header_labels = ["UUID", "Type", "Name", "StartInd", "EndInd", "Edge Anno", "Child C", "Child D"]
                        if column == 0:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].uuid)
                        elif column == 1:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].typ)
                        elif column == 2:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].name)
                        elif column == 3:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].startind)
                        elif column == 4:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].endind)
                        elif column == 5:
                            tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].edgeann)
                        elif column == 6:
                            if hasattr(ynode[1]['inode'], 'child_c'):
                                tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].child_c)
                            else:
                                tmp_item = self.QtGui.QTableWidgetItem(" ")
                        elif column == 7:
                            if hasattr(ynode[1]['inode'], 'child_d'):
                                tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].child_d)
                            else:
                                tmp_item = self.QtGui.QTableWidgetItem(" ")
                        tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                        self.taints_table.setItem(row, column, tmp_item)
                    self.taints_table.resizeRowToContents(row)
            self.taints_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.taints_table.resizeColumnsToContents()
            self.taints_table.setSortingEnabled(True)
            
    def insert_node_br(self, s, depth):
        from dispatcher.core.structures.Parse.TaintNode import TaintNode
        try:
            uuid = self.extract_uuid(s)
        except AttributeError:
            return
        if uuid is None:
            return
        if self.t_graph.has_node(uuid):
            return
        tempNode = TaintNode()
        tempNode.ExtractData(s)
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
        from dispatcher.core.structures.Parse.TaintNode import TaintNode
        tempNode = None
        try:
            uuid = self.extract_uuid(s)
        except AttributeError:
            return
        print uuid
        if self.t_graph.has_node(uuid):
            tempNode = self.t_graph.node[uuid]['inode']
            tempNode.ExtractData(s)
        else:
            tempNode = TaintNode()
            tempNode.ExtractData(s)
            self.t_graph.add_node(uuid, inode = tempNode)
        self.child_edges(tempNode)

    def child_edges(self, node):
        from dispatcher.core.structures.Parse.TaintNode import TaintNode
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
        Action for calling the trace functionality 
        """
        import sys
        import os
        #from optparse import OptionParser
        import logging
        import struct
        from dispatcher.core.structures.Analyzer import CIDTaintProp
        from dispatcher.core.structures.Analyzer.CIDParser import CIDATraceReader, CIDATextTraceReader, CIDAPinTraceReader
        
        from dispatcher.core.structures.Analyzer.CIDParser import Invalid, LoadImage, UnloadImage, Input, ReadMemory, WriteMemory, Execution, Snapshot, eXception
        from dispatcher.core.structures.Analyzer.CIDTaintProp import TaintPropagator
        from dispatcher.core.structures.Analyzer.CIDTaintProp import TAINT_NOPE,TAINT_ADDRESS,TAINT_BRANCH,TAINT_COUNTER,TAINT_DATA

        #if hasattr(self, trace_fname):
        #parser = OptionParser()
		
        if self.trace_fname is None:
            self.trace_table2.append('No trace file imported')
        else:
            log = logging.getLogger('CIDATA')
            
            if self.verbose_trace_cb.isChecked():
                logging.basicConfig(filename="debug.log",level=logging.DEBUG)
            else:
                logging.basicConfig(filename="warning.log",level=logging.INFO)
            processBits = 32
            #32Bit Check
            if(sys.maxsize > 2**32):
                processBits = 64
            targetBits = 32
            if (self.radioGroup.checkedButton().text() == "X86"):
                targetBits=32
            elif(self.radioGroup.checkedButton().text() == "X64"):
                targetBits=64
            if(self.pin_trace_cb.isChecked()):
                tr = CIDAPinTraceReader(self.trace_fname, self.index_fname)
                CIDTaintProp.traceType = CIDTaintProp.PIN
            else:
              tr = CIDATextTraceReader(self.trace_fname)
            CIDTaintProp.traceType = CIDTaintProp.IDA
            if tr is None:
                log.error("Failed to open trace file. Exit")
                self.trace_table2.append("Failed to open trace file.")
            out_str = "Processing trace file %s..." %(self.trace_fname)
            self.trace_table2.append(out_str)

            #Need to get the setting from GUI, default taint policy is TAINT_DATA:
            #taintPolicy = CIDTaintProp.TAINT_BRANCH # Used to test condOV;     
            taintPolicy = getattr(CIDTaintProp, self.radioGroup2.checkedButton().text(), "TAINT_DATA")
            #taint graph name begins with A(ddress), B(ranch), C(Counter) or D(ata) depending on policy
            fTaint = "TaintGraph_"+os.path.basename(self.trace_fname)
            if (taintPolicy == TAINT_BRANCH):
                fTaint = "BTaintGraph_"+os.path.basename(self.trace_fname)
            elif (taintPolicy == TAINT_DATA):
                fTaint = "DTaintGraph_"+os.path.basename(self.trace_fname)
            elif (taintPolicy == TAINT_COUNTER):
                fTaint = "CTaintGraph_"+os.path.basename(self.trace_fname)
            elif (taintPolicy == TAINT_ADDRESS):
                fTaint = "ATaintGraph_"+os.path.basename(self.trace_fname)				
            out_fd = open(fTaint, 'w')
            TP = TaintPropagator(processBits, targetBits, out_fd,taintPolicy)
			
            tRecord = tr.getNext()
            bEnd = False
            tNextRecord = None
            while tRecord!=None:
                tNextRecord = tr.getNext()
                recordType = tRecord.getRecordType()
                if (recordType == LoadImage):
                    if (self.verbose_trace_cb.isChecked()):
                        print("ImageName=%s, LoadAddr = %x, Size=%x" %(tRecord.ImageName, tRecord.LoadAddress, tRecord.ImageSize))
                        out_str = "ImageName=%s, LoadAddr = %x, Size=%x" %(tRecord.ImageName, tRecord.LoadAddress, tRecord.ImageSize)
                        self.trace_table2.append(out_str)                     
                elif (recordType == Input):
                    TP.SetInputTaint(tRecord.currentInputAddr, tRecord.currentInputSize)
                    if(self.verbose_trace_cb.isChecked()):
                        print("InputAddr = %x, InputSize =%x" %(tRecord.currentInputAddr, tRecord.currentInputSize))
                        out_str = "InputAddr = %x, InputSize =%x" %(tRecord.currentInputAddr, tRecord.currentInputSize)
                        self.trace_table2.append(out_str)
                elif(recordType == Execution):
                    if(tNextRecord.getRecordType() == eXception):
                        if(tNextRecord.currentExceptionCode ==0): # termination
                            TP.DumpLiveTaints()	
                        else:
                            TP.DumpFaultCause(tNextRecord, tRecord, self.verbose_trace_cb.isChecked())
                            print "Exception! Get out of the loop!"
                            bEnd = True
                            break        					
                    elif(TP.Propagator(tRecord)==1):
                        #bEnd = True
                        #if(self.verbose_trace_cb.isChecked()):
                        print "Tainted Security Warning!"
                        #break
                else:
                    print "Type %d not supported:%d" %recordType

                if (bEnd == True):
                    tRecord = None
                else:
                    tRecord = tNextRecord 				

            out_fd.close()
            out_fd = open(fTaint, 'r')
            self.f_taint = fTaint
            text=out_fd.read()
            self.trace_table2.setText(text)
            out_fd.close()
            log.info("CIDATA Finished")
            self.populateTaintsTable()
            self.populateTaintsOnGen()
            for x, y, d in self.t_graph.edges(data=True):
                print x
                print y
                print d
            self.extendTaints()
            self.parent.setTabFocus("Visualizer")
            self.parent.passTaintGraph(self.t_graph, "Visualizer", self.radioGroup2.checkedButton().text())
            self.parent.passTraceFile(self.trace_fname, "Visualizer")
            
    def extendTaints(self):
        """
        Method to extend taint information with trace. Library context added to taint nodes from trace
        """
        self.node_ea = dict()
        self.node_lib = dict()
        f=open(self.trace_fname, 'r')
        # read input file line by line
        for line in f:
            #Hard implementation of 'E' search
            if line.startswith('E'):
                splitted = line.split(' ')
                self.node_ea[splitted[5]] = splitted[1]
            #Hard implementation of 'L' search
            elif line.startswith('L'):
                splitted = line.split(' ')
                internal_str = splitted[2] + " " + splitted[3]
                self.node_lib[splitted[1]] = internal_str
            else:
                print ":"
        print "[debug] trace imported from file into dictionary"
        f.close()
        for node in self.t_graph.nodes(data=True):
            ind = node[1]['inode'].startind.split(':')[0]
            #if node[1]['inode'].endind is not None:
            #    ind = node[1]['inode'].endind.split(':')[0]
            try:
                addr = int(self.node_ea[ind], 16)
                node[1]['inode'].setEA(addr)
            except KeyError:
                node[1]['inode'].setEA(None)
            if node[1]['inode'].ea:
                for key in self.node_lib.keys():
                    base_addr = int(self.node_lib[key].split(' ')[0], 16)
                    end_addr = base_addr + int(self.node_lib[key].split(' ')[1], 16)
                    if node[1]['inode'].ea >= base_addr and node[1]['inode'].ea < end_addr:
                        print "Found library: %s" % key
                        node[1]['inode'].setLib(key)
                        break
        
            
    def onImportTraceButtonClicked(self):
        """ 
        Action for importing an XML file containing VM information
        """
        from dispatcher.core.structures.Parse import TrNode
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
        
    def _createTaintsTable(self):
        """
        Create the bottom left table
        """
        self.taints_table = QtGui.QTableWidget()
        #self.taints_table.doubleClicked.connect(self._onDetailsDoubleClicked)
    
    def _createTraceTable2(self):
        """
        Create the bottom right table
        """
        self.trace_table2 = QtGui.QTextEdit()
        #self.trace_table.doubleClicked.connect(self._onTraceDoubleClicked)
        
    def onTraceClicked(self, mi):
        """
        If a process is clicked, the view of the process and details are updated
        """
        self.clicked_trace = self.trace_table.item(mi.row(), 1).text()
        #self.populateTaintsTable(self.clicked_process)
        
    def traceTableWriter(self, text):
        """
        Writer method to append text to the trace table
        """
        self.trace_table2.append(text)
        
    def setTraceFile(self, t):
        """
        Method to set taint graph
        """
        print "%s trace file set, ready to go." % t