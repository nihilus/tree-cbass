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
import os
from collections import deque

class VisualizerWidget(QtGui.QMainWindow):
    """
    This widget is the front-end for the trace generations.
    """
    def __init__(self,parent):
        QtGui.QMainWindow.__init__(self)
        print "[|] loading VisualizerWidget"
        # Access to shared modules
        self.parent = parent
        self.name = "Visualizer"
        path = os.path.join(self.parent.iconPath,"trace.png")
        self.icon = QIcon(path)
        self.taint_queue = deque(maxlen=12)
        
        #References to qt-specific modules
        self.QtGui = QtGui
        self.QtCore = QtCore
        self.central_widget = self.QtGui.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()
        self.t_graph = nx.MultiDiGraph()
        #The taint graph object was added to prevent openning multiple instance the IDA Graphviewer
        self.taintGraph = None
        
    def _createGui(self):
        """
        Create the main GUI with its components
        """
        # Create buttons
        self.taint_nodes_label = QtGui.QLabel("Taint Nodes(0/0)")
        
        self._createToolbar()
        
        self._createTaintTable()
        #Layout information
        visualizer_layout = QtGui.QVBoxLayout()
        upper_table_widget = QtGui.QWidget()
        upper_table_layout = QtGui.QHBoxLayout()
        
        upper_table_layout.addWidget(self.taint_table)
        upper_table_widget.setLayout(upper_table_layout)
        
        splitter = self.QtGui.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = QtGui.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(upper_table_widget)
        visualizer_layout.addWidget(splitter)
        
        self.central_widget.setLayout(visualizer_layout)
        
    def _createToolbar(self):
        """
        Create the toolbar
        """
        self._createRefreshAction()
        #self._createImportTraceAction()
        self._createIDAGraphAction()
        
        self.toolbar = self.addToolBar('Trace Generation Toolbar')
        self.toolbar.addAction(self.refreshAction)
        self.toolbar.addAction(self.importIDAGraphAction)
        
    def _createRefreshAction(self):
        """
        Create the refresh action for the oolbar. triggers a scan of virtualmachines and updates the GUI.
        """
        path = os.path.join(self.parent.iconPath,"refresh.png")
        self.refreshAction = QtGui.QAction(QIcon(path), "Refresh the " \
            + "view", self)
        self.refreshAction.triggered.connect(self._onRefreshButtonClicked)
        
    def _createImportTraceAction(self):
        """
        Create the import trace action
        """
        path = os.path.join(self.parent.iconPath,"import.png")
        self.importTraceAction = QtGui.QAction(QIcon(path), "Import the trace file", self)
        self.importTraceAction.triggered.connect(self.onImportTraceButtonClicked)
        
    def _createIDAGraphAction(self):
        """
        Create the import trace action
        """
        path = os.path.join(self.parent.iconPath,"online.png")
        self.importIDAGraphAction = QtGui.QAction(QIcon(path),"Generate IDA Graph", self)
        self.importIDAGraphAction.triggered.connect(self.onIDAGraphClicked)
        
    def _createTaintTable(self):
        """
        Create the top table used for showing all
        """
        self.taint_table = QtGui.QTableWidget()
        self.taint_table.clicked.connect(self.onTaintClicked)
        #self.taint_table.doubleClicked.connect(self.onProcessDoubleClicked)
        
    def populateTaintTable(self):
        """
        Populate the VM table with information about the virtual machines
        """
        #If no config then connect to virtualbox in config
        self.taint_table.setSortingEnabled(False)
        if self.policy == "TAINT_BRANCH":
            self.taints_header_labels = ["UUID", "Type", "Name", "Start Sequence", "End Sequence", "Transformation Instruction"]
        else:
            self.taints_header_labels = ["UUID", "Type", "Name", "Start Sequence", "End Sequence", "Transformation Instruction", "Child C", "Child D"]
        self.taint_table.clear()
        self.taint_table.setColumnCount(len(self.taints_header_labels))
        self.taint_table.setHorizontalHeaderLabels(self.taints_header_labels)
        self.taint_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.taint_table.resizeColumnsToContents()
        self.taint_table.verticalHeader().setVisible(False)
        self.taint_table.setSortingEnabled(True)
        
    def _onRefreshButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        self.clearTableRowHighlight(self.taint_table)
        
    def updateTaintsLabel(self,n1, n2):
        """
        Action for updating the TaintsLabel
        """
        self.taint_nodes_label.setText("Taint Nodes(%d/%d)" %
            (n1, n2))
            
    def insert_node(self, s):
        from ..core.structures.Parse.TaintNode import TaintNode
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
            
    def onImportTraceButtonClicked(self):
        """ 
        Action for importing an XML file containing VM information
        """
        #from ..core.structures.Parse import TrNode
        fname, _ = self.QtGui.QFileDialog.getOpenFileName(self, 'Import Trace')
        self.trace_fname = fname
        #self.populateTraceTable()
        
    def onIDAGraphClicked(self):
        """ 
        Action for generating the IDA Graph
        """
        #self.populateTraceTable()
        from ..core.structures.Graph.TaintGraph import TaintGraph
        from ..core.structures.Graph.BCTaintGraph import BCTaintGraph
        
        if self.taintGraph is not None:
          print "Closing taint graph"
          self.taintGraph.Close()
          
        if self.policy == "TAINT_BRANCH":
            self.taintGraph = BCTaintGraph(self.t_graph)
        else:
            self.taintGraph = TaintGraph(self.t_graph)
        self.taintGraph.Show()
        
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
        
    def traceTableWriter(self, text):
        """
        Writer method to append text to the trace table
        """
        self.taint_table2.append(text)
        
    def setTaintGraph(self, t, p):
        """
        Method to set taint graph
        """
        self.t_graph = t
        self.policy = p
        self.populateTaintTable()
        self.populateTaintsTableImported()
        
    def populateTaintsTableImported(self):
        """
        Method for populating the taints table
        """
        self.taint_table.setRowCount(len(self.t_graph))
        self.taint_table.setContextMenuPolicy(self.QtCore.Qt.CustomContextMenu)
        self.taint_table.customContextMenuRequested.connect(self.handleTaintMenu)
        self.taint_table.cellClicked.connect(self.childClick)
        if self.policy == "TAINT_BRANCH":
            for row, ynode in enumerate(self.t_graph.nodes(data=True)):
                for column, column_name in enumerate(self.taints_header_labels):
                    tmp_item = None
                    if column == 0:
                        tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].uuid)
                    elif column == 1:
                        typ = ''
                        if ynode[1]['inode'].typ == "in":
                            typ = "input"
                        elif ynode[1]['inode'].typ == "mem":
                            typ = "memory"
                        elif ynode[1]['inode'].typ == "reg":
                            typ = "register"
                        tmp_item = self.QtGui.QTableWidgetItem(typ)
                    elif column == 2:
                        tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].name)
                    elif column == 3:
                        tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].startind)
                    elif column == 4:
                        tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].endind)
                    elif column == 5:
                        tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].edgeann)
                    tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                    self.taint_table.setItem(row, column, tmp_item)
                self.taint_table.resizeRowToContents(row)
        else:
            for row, ynode in enumerate(self.t_graph.nodes(data=True)):
                for column, column_name in enumerate(self.taints_header_labels):
                    ##@self.process_header_labels = ["UUID", "Type", "Name", "StartInd", "EndInd", "Edge Anno", "Child C", "Child D"]
                    if column == 0:
                        tmp_item = self.QtGui.QTableWidgetItem(ynode[1]['inode'].uuid)
                    elif column == 1:
                        typ = ''
                        if ynode[1]['inode'].typ == "in":
                            typ = "input"
                        elif ynode[1]['inode'].typ == "mem":
                            typ = "memory"
                        elif ynode[1]['inode'].typ == "reg":
                            typ = "register"
                        tmp_item = self.QtGui.QTableWidgetItem(typ)
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
                            #self.QtCore.QObject.connect(tmp_item, self.QtCore.SIGNAL('clicked()'), self.childDoubleClick)
                        else:
                            tmp_item = self.QtGui.QTableWidgetItem(" ")
                    tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                    self.taint_table.setItem(row, column, tmp_item)
                self.taint_table.resizeRowToContents(row)
            self.taint_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.taint_table.resizeColumnsToContents()
            self.taint_table.setSortingEnabled(True)
            
    def handleTaintMenu(self, pos):
        menu = self.QtGui.QMenu()
        addr = self.QtGui.QAction("Go to address", menu)
        addr.setStatusTip("Go to address within IDA")
        self.connect(addr, self.QtCore.SIGNAL('triggered()'), self.addrGo)
        menu.addAction(addr)
        menu.exec_(self.QtGui.QCursor.pos())
        
    def childClick(self, x, y):
        if y == 6:
            self.clearTableRowHighlight(self.taint_table)
            self.highlightTaintChildren(x,y,0)
        elif y == 7:
            self.clearTableRowHighlight(self.taint_table)
            self.highlightTaintChildren(x,y,0)
            #self.taint_table.item(x,y).setBackground(self.QtCore.Qt.red)
            
    def highlightTaintChildren(self, x, y, depth):
        #Clear current taints
        #Keep in mind cells are initialized to " "
        #print type(self.taint_table.findItems(self.taint_table.item(x,y).text(), self.QtCore.Qt.MatchExactly))
        if(depth >3):
            return
        elif not self.taint_table.item(x,y).text().strip():
            return
        else:
            for child in self.taint_table.item(x,y).text().split(" "):
                #Search for child's row in taint_table
                row = self.tableSearch(self.taint_table, child)
                self.highlightRow(self.taint_table, row, self.QtCore.Qt.red)
                self.highlightTaintChildren(row, y, depth+1)
                return
        return
            
    def tableSearch(self, table, val):
        """
        Search through every row in the uuid for a value and retun the corresponding row
        """
        row = None
        for i in xrange(table.rowCount()):
            if int(table.item(i,0).text()) == int(val):
                row = i
                break
        return row
        
    def highlightRow(self, table, row, color):
        """
        """
        for i in xrange(len(self.taints_header_labels)):
            table.item(row,i).setBackground(color)
        
    def clearTableHighlight(self, table, column):
        """
        """
        for i in xrange(table.rowCount()):
            self.taint_table.item(i,column).setBackground(self.QtCore.Qt.white)
        
    def clearTableRowHighlight(self, table):
        """
        """
        for i in xrange(table.rowCount()):
            for j in xrange(len(self.taints_header_labels)):
                self.taint_table.item(i,j).setBackground(self.QtCore.Qt.white)
        
    def addrGo(self):
        from idc import *
        uuid = self.taint_table.item(self.taint_table.currentItem().row(), 0).text()
        bLoaded = isLoaded(self.t_graph.node[uuid]['inode'].ea)
        if bLoaded:
          print "Found addr: 0x%x" % self.t_graph.node[uuid]['inode'].ea
          idc.Jump(self.t_graph.node[uuid]['inode'].ea)
        #self.filters_filename_table.insertRow(self.filters_filename_table.rowCount())
        #self.filters_filename_table.setItem(self.filters_filename_table.rowCount()-1, 0, self.QtGui.QTableWidgetItem(" "))