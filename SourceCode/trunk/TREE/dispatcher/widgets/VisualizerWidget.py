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
        self.icon = QIcon(self.parent.iconPath + "trace.png")
        
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
        # Create buttons
        self.taint_nodes_label = QtGui.QLabel("Taint Nodes(0/0)")
        
        self._createToolbar()
        
        self._createTaintTable()
        #Layout information
        visualizer_layout = QtGui.QVBoxLayout()
        upper_table_widget = QtGui.QWidget()
        upper_table_layout = QtGui.QVBoxLayout()
        upper_table_layout.addWidget(self.taint_table)
        upper_table_widget.setLayout(upper_table_layout)
        
        lower_tables_widget = QtGui.QWidget()
        lower_tables_layout = QtGui.QVBoxLayout()
        
        #lower_tables_layout.addWidget(QtGui.QGraphicsView(QtGui.QGraphicsScene()))
        #lower_tables_layout.addWidget(self.graphView)
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
        self._createImportTraceAction()
        self._createImportIndexAction()
        self._createIDAGraphAction()
        
        self.toolbar = self.addToolBar('Trace Generation Toolbar')
        self.toolbar.addAction(self.refreshAction)
        #self.toolbar.addAction(self.importTraceAction)
        self.toolbar.addAction(self.importIDAGraphAction)
        
    def _createRefreshAction(self):
        """
        Create the refresh action for the oolbar. triggers a scan of virtualmachines and updates the GUI.
        """
        self.refreshAction = QtGui.QAction(QIcon(self.parent.iconPath + "refresh.png"), "Refresh the " \
            + "view", self)
        self.refreshAction.triggered.connect(self._onRefreshButtonClicked)
        
        
    def _createImportTraceAction(self):
        """
        Create the import trace action
        """
        self.importTraceAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "import.png"),
            "Import the trace file", self)
        self.importTraceAction.triggered.connect(self.onImportTraceButtonClicked)
        
    def _createIDAGraphAction(self):
        """
        Create the import trace action
        """
        self.importIDAGraphAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "online.png"),
            "Generate IDA Graph", self)
        self.importIDAGraphAction.triggered.connect(self.onIDAGraphClicked)
        
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
        
    def updateTaintsLabel(self,n1, n2):
        """
        Action for updating the TaintsLabel
        """
        self.taint_nodes_label.setText("Taint Nodes(%d/%d)" %
            (n1, n2))
            
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
            
    def onImportTraceButtonClicked(self):
        """ 
        Action for importing an XML file containing VM information
        """
        from dispatcher.core.structures.Parse import TrNode
        fname, _ = self.QtGui.QFileDialog.getOpenFileName(self, 'Import Trace')
        self.trace_fname = fname
        #self.populateTraceTable()
        
    def onIDAGraphClicked(self):
        """ 
        Action for generating the IDA Graph
        """
        #self.populateTraceTable()
        from dispatcher.core.structures.Graph.TaintGraph import TaintGraph
        from dispatcher.core.structures.Graph.BCTaintGraph import BCTaintGraph
        if self.policy == "TAINT_BRANCH":
            tv = BCTaintGraph(self.t_graph, self.node_ea)
        else:
            tv = TaintGraph(self.t_graph, self.node_ea, self.node_lib)
        tv.Show()
    
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
        
    def setTraceFile(self, t):
        """
        Method to set taint graph
        """
        self.node_ea = dict()
        self.node_lib = dict()
        f=open(t, 'r')
        # read input file line by line
        tempNode = None
        for line in f:
            #Hard implementation of 'E' search
            if line.startswith('E'):
                splitted = line.split(' ')
                self.node_ea[splitted[5]] = splitted[1]
            #Hard implementation of 'L' search
            elif line.startswith('L'):
                splitted = line.split(' ')
                self.node_lib[splitted[1]] = (str(splitted[2]) + " " + str(splitted[3]))
        print "[debug] trace imported from file into dictionary"
        f.close()