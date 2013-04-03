try:
  import networkx as nx
  NetworkX = True
except:
  print "[debug] No Networkx library support"
  pass
from PySide import QtGui, QtCore
from PySide.QtGui import QIcon
from idaapi import *
from idautils import *
from idc import *
from dispatcher.core.structures.Graph.PySideGraph import *

class ConcurrencyWidget(QtGui.QMainWindow):
    """
    This widget is the front-end for the trace generations.
    """
    def __init__(self,parent):
        QtGui.QMainWindow.__init__(self)
        print "[|] loading ConcurrencyWidget"
        # Access to shared modules
        self.parent = parent
        self.name = "Concurrency"
        self.icon = QIcon(self.parent.config.icon_file_path + "trace.png")
        
        #References to qt-specific modules
        self.QtGui = QtGui
        self.QtCore = QtCore
        #self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self.central_widget = self.QtGui.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()
        self.t_graph = nx.MultiDiGraph()
        
    def _createGui(self):
        """
        Create the main GUI with its components
        """
        
        self._createToolbar()
        
        self._createTaintTable()
        #self._createGraphView()
        self.graphView = QtGui.QGraphicsView()
        #Layout information
        visualizer_layout = QtGui.QVBoxLayout()
        upper_table_widget = QtGui.QWidget()
        upper_table_layout = QtGui.QVBoxLayout()
        upper_table_layout.addWidget(self.taint_table)
        upper_table_widget.setLayout(upper_table_layout)
        
        lower_tables_widget = QtGui.QWidget()
        lower_tables_layout = QtGui.QVBoxLayout()
        
        lower_tables_layout.addWidget(self.graphView)
        lower_tables_widget.setLayout(lower_tables_layout)
        
        splitter = self.QtGui.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = QtGui.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(upper_table_widget)
        splitter.addWidget(lower_tables_widget)
        visualizer_layout.addWidget(splitter)
        
        self.central_widget.setLayout(visualizer_layout)
        self.populateTaintTable()
        #self.populateVMTable()
        #self.updateVMLabel()
        
    def _createToolbar(self):
        """
        Create the toolbar
        """
        self._createRefreshAction()
        self._createImportThreadAction()
        self._createAnalyzeAction()
        
        self.toolbar = self.addToolBar('Concurrency Analyzer Toolbar')
        self.toolbar.addAction(self.refreshAction)
        self.toolbar.addAction(self.importThreadAction)
        self.toolbar.addAction(self.generateAnalyzeAction)
        
    def _createRefreshAction(self):
        """
        Create the refresh action for the oolbar. triggers a scan of virtualmachines and updates the GUI.
        """
        self.refreshAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + "refresh.png"), "Refresh the " \
            + "view by scanning all the processes again", self)
        self.refreshAction.triggered.connect(self._onRefreshButtonClicked)
        
    def _createAnalyzeAction(self):
        """
        Create that action that performs the trace
        """
        self.generateAnalyzeAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + \
            "trace.png"), "Generate the trace.", self)
        self.generateAnalyzeAction.triggered.connect(self.onStartAnalyzeButtonClicked)
        
    def _createImportThreadAction(self):
        """
        Create the import trace action
        """
        self.importThreadAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path +
        "import.png"),
            "Import the thread file", self)
        self.importThreadAction.triggered.connect(self.onImportThreadButtonClicked)
        
    def _createTaintTable(self):
        """
        Create the top table used for showing all
        """
        self.taint_table = QtGui.QTableWidget()
        self.taint_table.clicked.connect(self.onTaintClicked)
        #self.taint_table.doubleClicked.connect(self.onProcessDoubleClicked)
        
    def _createGraphView(self):
        from dispatcher.core.structures.Graph.PySideGraph import *
        self.graphScene = self.QtGui.QGraphicsScene()
        self.graphScene.setSceneRect(0,0,800,600)

        #Select node connection and its decorator types
        nc = CenterCalc()
        cd = LineArrowOnStart()          

        cur_thread = [[]*(self.thread_count+1) for x in xrange(self.thread_count+1)]
        cur_num = 0
        for thread in self.thread_list:
            node = None
            cur_x = int(thread.t1)*(800/self.thread_count)
            cur_y = (600/len(self.thread_list))*cur_num
            print thread.label()
            if not cur_thread[int(thread.t1)]:
                node = TextNode(nc, cd, None, thread.e, thread.label(), cur_x, cur_y, 200, 30)
                cur_thread[int(thread.t1)].append(node)
            else:
                node = TextNode(nc, cd, cur_thread[int(thread.t1)][-1], thread.e, thread.label(), cur_x, cur_y, 200, 30)
                cur_thread[int(thread.t1)].append(node)
            self.graphScene.addItem(node)
            cur_num = cur_num + 1

        self.graphView.setScene(self.graphScene)
        self.graphView.update()
        self.graphView.repaint()
        
    def populateTaintTable(self):
        """
        Populate the VM table with information about the virtual machines
        """
        #If no config then connect to virtualbox in config
        self.taint_table.setSortingEnabled(False)
        self.trace_header_labels = ["UUID", "Type", "Name", "StartInd", "EndInd", "Edge Anno", "Child C", "Child D"]
        self.taint_table.clear()
        self.taint_table.setColumnCount(len(self.trace_header_labels))
        self.taint_table.setHorizontalHeaderLabels(self.trace_header_labels)
        if hasattr(self, 'f_taint'):
            processes = self.t_config.root.findall('process')
            self.taint_table.setRowCount(len(processes))
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
                    self.taint_table.setItem(row, column, tmp_item)
                self.taint_table.resizeRowToContents(row)
            self.taint_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.taint_table.resizeColumnsToContents()
            self.taint_table.setSortingEnabled(True)
        else:
            self.taint_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.taint_table.resizeColumnsToContents()
            self.taint_table.setSortingEnabled(True)
            
    def populateTaintsTable(self):
        """
        Populate the details table based on the selected process in the process table.
        For no uneditable
        @Todo:
            Make editable and have changes pushed out to file
        """
        self.taints_table.setSortingEnabled(False)
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
        #for i in self.graphScene.items():
        #    self.graphScene.removeItem(i)
        self._createGraphView()
            
    def populateTaintsOnGen(self):
        """
        Action for refreshing the window data by checking each process
        """
        if hasattr(self, 'f_taint'):
            #import taint file
            taint_in = open(self.f_taint, 'r')
            for line in taint_in:
                self.insert_node(line.rstrip('\n'))
            self.t_graph.reverse(copy=False)
            
            self.taints_table.setRowCount(len(self.t_graph))
            self.updateTaintsLabel(len(self.t_graph), len(self.t_graph))
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
            
    def insert_node(self, s):
        from dispatcher.core.structures.Parse.TaintNode import TaintNode
        tempNode = None
        uuid = self.extract_uuid(s)
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
        #if hasattr(self, trace_fname):
        #parser = OptionParser()
		
        if self.trace_fname is None:
            self.taint_table2.append('No trace file imported')
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
                self.taint_table2.append("Failed to open trace file.")
            out_str = "Processing trace file %s..." %(self.trace_fname)
            self.taint_table2.append(out_str)
            fTaint = "TaintGraph_"+os.path.basename(self.trace_fname)
            out_fd = open(fTaint, 'w')
            #self.out_fd = open(fTaint, 'r+b')
            
            TP = TaintPropagator(processBits, targetBits, out_fd)
            tRecord = tr.getNext()
            bEnd = False
            tLastRecord = None
            while tRecord!=None:
                recordType = tRecord.getRecordType()
                if (recordType == LoadImage):
                    if (self.verbose_trace_cb.isChecked()):
                        print("ImageName=%s, LoadAddr = %x, Size=%x" %(tRecord.ImageName, tRecord.LoadAddress, tRecord.ImageSize))
                elif (recordType == Input):
                    TP.SetInputTaint(tRecord.currentInputAddr, tRecord.currentInputSize)
                    if(self.verbose_trace_cb.isChecked()):
                        print("InputAddr = %x, InputSize =%x" %(tRecord.currentInputAddr, tRecord.currentInputSize))
                        out_str = "InputAddr = %x, InputSize =%x" %(tRecord.currentInputAddr, tRecord.currentInputSize)
                        self.taint_table2.append(out_str)
                elif(recordType == Execution):
                    tLastRecord = tRecord
                    if(TP.Propagator(tRecord)==1):
                        bEnd = True
                        if(self.verbose_trace_cb.isChecked()):
                            print "Tainted Security Warning!"
                        break
                elif(recordType == eXception):
                    if(tLastRecord != None):
                        TP.DumpFaultCause(tRecord, self.verbose_trace_cb.isChecked())
                        print "Exception! Get out of the loop!"
                        bEnd = True
                        break
                else:
                    print "Type %d not supported:%d" %recordType
                if (bEnd == True):
                    tRecord = None
                else:
                    tRecord = tr.getNext()
            out_fd.close()
            out_fd = open(fTaint, 'r')
            self.f_taint = fTaint
            text=out_fd.read()
            self.taint_table2.setText(text)
            out_fd.close()
            log.info("CIDATA Finished")
            self.populateTaintsOnGen()
            
            
    def onImportThreadButtonClicked(self):
        """ 
        Action for importing an XML file containing VM information
        """
        fname, _ = self.QtGui.QFileDialog.getOpenFileName(self, 'Import Concurrency File')
        self.thread_fname = fname
        self.parseThreads()
        self._onRefreshButtonClicked()
        #self.populateTraceTable()
        
    def parseThreads(self):
        """
        Action for parsing thread nodes from file
        """
        from dispatcher.core.structures.Parse.ThreadNode import ThreadNode
        self.thread_list = []
        f = open(self.thread_fname, 'r')
        self.thread_count = 0
        for line in f:
            print line
            tempNode = ThreadNode()
            tempNode.extractData(line.strip())
            tempNode.parseMessage()
            self.thread_list.append(tempNode)
            if tempNode.t1 > self.thread_count:
                self.thread_count = int(tempNode.t1)
            print tempNode.label()
    
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
        self.taint_table2 = QtGui.QTextEdit()
        #self.taint_table.doubleClicked.connect(self._onTraceDoubleClicked)
        
    def onTaintClicked(self, mi):
        """
        If a process is clicked, the view of the process and details are updated
        """
        self.clicked_trace = self.taint_table.item(mi.row(), 1).text()
        #self.populateTaintsTable(self.clicked_process)
        