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
from ..core.structures.Graph.PySideGraph import *

class ReplayerWidget(QtGui.QMainWindow):
    """
    This widget is the front-end for the trace generations.
    """
    def __init__(self,parent):
        QtGui.QMainWindow.__init__(self)
        print "[|] loading ReplayerWidget"
        # Access to shared modules
        self.parent = parent
        self.name = "Replayer"
        self.icon = QIcon(self.parent.iconPath + "trace.png")
        
        #References to qt-specific modules
        self.QtGui = QtGui
        self.QtCore = QtCore
        self.central_widget = self.QtGui.QWidget()
        self.setCentralWidget(self.central_widget)
        self._definePropEnum()
        self._createGui()
        self.t_graph = nx.MultiDiGraph()
        
    def _createGui(self):
        """
        Create the main GUI with its components
        """
        # Create buttons
        self.taint_nodes_label = QtGui.QLabel("Taint Nodes(0/0)")
        
        self._createToolbar()
        self._createTraceTable()
        self._createTaintTable()
        #Layout information
        self.graphView = QtGui.QGraphicsView()
        visualizer_layout = QtGui.QVBoxLayout()
        
        upper_table_widget = QtGui.QWidget()
        upper_tables_layout = QtGui.QHBoxLayout()
        
        
        lower_tables_widget = QtGui.QTabWidget()
        tab1 = QtGui.QWidget()
        tab2 = QtGui.QWidget()
        tab3 = QtGui.QWidget()
        tab4 = QtGui.QWidget()
        lower_tables_widget.addTab(tab1, "Stack")
        lower_tables_widget.addTab(tab2, "Heap")
        lower_tables_widget.addTab(tab3, "Taint")
        lower_tables_widget.addTab(tab4, "Concurrency")
        
        #lower_tables_layout.addWidget(QtGui.QGraphicsView(QtGui.QGraphicsScene()))
        upper_tables_layout.addWidget(self.graphView)
        upper_tables_layout.addWidget(self.trace_table)
        upper_table_widget.setLayout(upper_tables_layout)
        
        splitter = self.QtGui.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = QtGui.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(upper_table_widget)
        splitter.addWidget(lower_tables_widget)
        visualizer_layout.addWidget(splitter)
        
        self.central_widget.setLayout(visualizer_layout)
        #self.populateTaintTable()
        
    def _createToolbar(self):
        """
        Create the toolbar
        """
        self._createImportTraceAction()
        self._createTaintMarkAction()
        self._createForwardAction()
        self._createFastForwardAction()
        self._createInfoAction()
        self._createZoomAction()
        self._createBackwardAction()
        self._createRewindAction()
        self._createTaintCheckAction()
        
        self.toolbar = self.addToolBar('Trace Generation Toolbar')
        self.toolbar.addAction(self.importTraceAction)
        self.toolbar.addAction(self.taintMarkAction)
        self.toolbar.addAction(self.forwardAction)
        self.toolbar.addAction(self.fastForwardAction)
        self.toolbar.addAction(self.infoAction)
        self.toolbar.addAction(self.zoomAction)
        self.toolbar.addAction(self.rewindAction)
        self.toolbar.addAction(self.backwardAction)
        self.toolbar.addAction(self.taintCheckAction)
        
    def _definePropEnum(self):
        """
        Generate the taint propagation policies
        """
        self.layout_prop = []
        self.layout_prop.append("Spring")
        self.layout_prop.append("Circular")
        self.layout_prop.append("Shell")
        self.layout_prop.append("Spectral")
        self.layout_prop.append("Standard")
        
    def _createTraceTable(self):
        """
        Create the top table used for showing all
        """
        self.trace_table = QtGui.QTableWidget()
        #self.trace_table.clicked.connect(self.onTaintClicked)
        #self.taint_table.doubleClicked.connect(self.onProcessDoubleClicked)
        
    def _createImportTraceAction(self):
        """
        Create the refresh action for the oolbar. triggers a scan of virtualmachines and updates the GUI.
        """
        self.importTraceAction = QtGui.QAction(QIcon(self.parent.iconPath + "import.png"), "Import trace", self)
        self.importTraceAction.triggered.connect(self._onImportTraceButtonClicked)
        
    def _createTaintMarkAction(self):
        """
        Create the refresh action for the oolbar. triggers a scan of virtualmachines and updates the GUI.
        """
        self.taintMarkAction = QtGui.QAction(QIcon(self.parent.iconPath + "taintmark.png"), "Mark a " \
            + "taint", self)
        self.taintMarkAction.triggered.connect(self._onTaintMarkButtonClicked)
        
    def _createForwardAction(self):
        """
        Create the import trace action
        """
        self.forwardAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "forward.png"),
            "Forward", self)
        self.forwardAction.triggered.connect(self._onForwardButtonClicked)
        
    def _createFastForwardAction(self):
        """
        Create the import trace action
        """
        self.fastForwardAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "fastforward.png"),
            "Fast Forward", self)
        self.fastForwardAction.triggered.connect(self._onFastForwardButtonClicked)
        
    def _createInfoAction(self):
        """
        Create the import trace action
        """
        self.infoAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "info.png"),
            "Info", self)
        self.infoAction.triggered.connect(self._onInfoButtonClicked)
        
    def _createZoomAction(self):
        """
        Create the import trace action
        """
        self.zoomAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "zoom.png"),
            "Zoom", self)
        self.zoomAction.triggered.connect(self._onZoomButtonClicked)
        
    def _createBackwardAction(self):
        """
        Create the import trace action
        """
        self.backwardAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "backward.png"),
            "Backwards", self)
        self.backwardAction.triggered.connect(self._onBackwardButtonClicked)
        
    def _createRewindAction(self):
        """
        Create the import trace action
        """
        self.rewindAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "rewind.png"),
            "Rewind", self)
        self.rewindAction.triggered.connect(self._onRewindButtonClicked)
        
    def _createTaintCheckAction(self):
        """
        Create the import trace action
        """
        self.taintCheckAction = QtGui.QAction(QIcon(self.parent.iconPath +
        "taintcheck.png"),
            "Taint Check", self)
        self.taintCheckAction.triggered.connect(self._onTaintCheckButtonClicked)
        
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
            self.taints_header_labels = ["UUID", "Type", "Name", "StartInd", "EndInd", "Edge Anno"]
        else:
            self.taints_header_labels = ["UUID", "Type", "Name", "StartInd", "EndInd", "Edge Anno", "Child C", "Child D"]
        self.taint_table.clear()
        self.taint_table.setColumnCount(len(self.taints_header_labels))
        self.taint_table.setHorizontalHeaderLabels(self.taints_header_labels)
        self.taint_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.taint_table.resizeColumnsToContents()
        self.taint_table.setSortingEnabled(True)
        
    def _onImportTraceButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        #self._createGraphView()
        fname, _ = self.QtGui.QFileDialog.getOpenFileName(self, 'Import Trace')
        self.trace_fname = fname
        self.populateTraceTable()
        #self.genTraceTable()
        
        
    def _onTaintMarkButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        #self._createGraphView()
        print "test"
        
    def _onForwardButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        #self._createGraphView()
        print "test"
        
    def _onFastForwardButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        #self._createGraphView()
        print "test"
        
    def _onInfoButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        #self._createGraphView()
        print "test"
        
    def _onZoomButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        #self._createGraphView()
        print "test"
        
    def _onBackwardButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        #self._createGraphView()
        print "test"
        
    def _onRewindButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        #self._createGraphView()
        print "test"
        
    def _onTaintCheckButtonClicked(self):
        """
        Action for refreshing the window data by checking each process
        """
        #self._createGraphView()
        print "test"
        
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
            
    def onForwardButtonClicked(self):
        """ 
        Action for importing an XML file containing VM information
        """
        #self.populateTraceTable()
        print "forward"
        
    def onIDAGraphClicked(self):
        """ 
        Action for generating the IDA Graph
        """
        #self.populateTraceTable()
        from ..core.structures.Graph.TaintGraph import TaintGraph
        from ..core.structures.Graph.BCTaintGraph import BCTaintGraph
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
        self.populateTaintTable()
        self.populateTaintsTableImported()
        self._createGraphView() 
        
    def _createGraphView(self):
        from ..core.structures.Graph.PySideGraph import *
        import networkx as nx
        self.graphScene = self.QtGui.QGraphicsScene()
        self.graphScene.setSceneRect(0,0,800,600)
        #pos = nx.shell_layout(self.t_graph, scale=800)
        pos = nx.circular_layout(self.t_graph, scale=800)
        if (self.radioGroup2.checkedButton().text() == "Spring"):
            pos = nx.spring_layout(self.t_graph, scale=800)
        elif (self.radioGroup2.checkedButton().text() == "Circular"):
            pos = nx.circular_layout(self.t_graph, scale=800)
        elif (self.radioGroup2.checkedButton().text() == "Shell"):
            pos = nx.shell_layout(self.t_graph, scale=800)
        elif (self.radioGroup2.checkedButton().text() == "Spectral"):
            pos = nx.spectral_layout(self.t_graph, scale=800)
        else:
            #standard
            #pos = nx.circular_layout(self.t_graph, scale=800)
            if self.policy == "TAINT_BRANCH":
                self.genStandardLayoutBranch(self.t_graph, scale=800)
            else:
                pos = self.genStandardLayout(self.t_graph, scale=800)
        #Select node connection and its decorator types
        nc = CenterCalc()
        cd = LineArrowOnStart()      
        node_dict = dict() #must contain the textnode object for parent lookup
        for x,y in self.t_graph.nodes(data=True):
            node = None
            node_p = None
            #Current Logic:
            #Create a node 
            #Create the children of the node
            #there will be conflicts
            #Must check if the child already exists and link it to parent
            if not str(x) in node_dict:
                cur_x = int(float(pos[str(x)][0]))
                cur_y = int(float(pos[str(x)][1]))
                node_p = TextNode(nc, cd, None, str(x), y['inode'].label(), cur_x, cur_y, 200, 30)
                #self.graphScene.addItem(node_p)
                node_dict[str(x)] = node_p
            for attr, value in y['inode'].__dict__.iteritems():
                if(attr.startswith('child')):
                    a = getattr(y['inode'], attr)
                    if a is not None:
                        for child in a.split():
                            child_x = int(float(pos[child][0]))
                            child_y = int(float(pos[child][1]))
                            node = TextNode(nc, cd, node_dict[str(x)], child, self.t_graph.node[child]['inode'].label(), child_x, child_y, 200, 30)
                            #self.graphScene.addItem(node)
                            node_dict[child] = node
        for x,y in node_dict.iteritems():
            self.graphScene.addItem(y)
        self.graphView.setScene(self.graphScene)
        self.graphView.update()
        self.graphView.repaint()
        
    def genStandardLayout(self, t_graph, scale):
        import networkx as nx
        roots = [n for n,d in t_graph.in_degree().items() if d == 0]
        topo = nx.topological_sort(t_graph)
        std_layout = dict()
        x_counter = 0
        y_counter = 0
        y_chain_length = 20
        for i in topo:
            if i in roots:
                x_counter = x_counter + 1
                y_counter = 0
            cur_x = x_counter*(800/len(roots))
            cur_y = (600/y_chain_length)*y_counter
            y_counter = y_counter + 1
            A = []
            A.append(cur_x)
            A.append(cur_y)
            std_layout[i] = A
            #print std_layout[i][0]
            #print std_layout[i][1]
        return std_layout
            
    def genStandardLayout2(self, t_graph, scale):
        from networkx.algorithms.traversal.depth_first_search import dfs_tree
        numChains = 0
        roots = [n for n,d in t_graph.out_degree().items() if d == 0]
        #print roots
        for i in roots:
            #print t_graph.node[i]['inode'].child_d
            #print type(t_graph.node[i])
            print self.getTreeDepth(dfs_tree(t_graph,i), 1)
            #children = [n for n,d in 
            
    def crawlTreeStd(self, t_graph, num):
        from networkx.algorithms.traversal.depth_first_search import dfs_tree
        root = t_graph.root()
        print type(root)
        #self.std_layout[
        if root.hasNoChildren(): return
        #for child in root.children():
        if not t_graph.size() <= 1:
            for attr, value in t_graph.node[i]['inode']:
                if(attr.startswith('child')):
                    a = getattr(t_graph.node[i]['inode'], attr)
        else:
            print "else"
            
            
    def getTreeDepth(self, t_graph, num):
        from networkx.algorithms.traversal.depth_first_search import dfs_tree
        if not t_graph.size() <= 1:
            for attr, value in t_graph.node[i]['inode']:
                if(attr.startswith('child')):
                    a = getattr(t_graph.node[i]['inode'], attr)
                    if a is not None:
                        curChildMax = 0
                        for child in a.split():
                            a = self.getTreeDepth(dfs_tree(t_graph,child), num+1)
                            if a > curChildMax:
                                curChildMax = a
                        return curChildMax + num
                    else:
                        return num
        else:
            return num
            
    def genStandardLayoutBranch(self, t_graph, scale):
        #
        # Branch depth-based layout, columns are chain sequences
        # Rows are depth levels
        #
        numChains = 0
        
    def _createGraphView2(self, A):
        from ..core.structures.Graph.PySideGraph import *
        self.graphScene = self.QtGui.QGraphicsScene()
        self.graphScene.setSceneRect(0,0,800,600)

        #Select node connection and its decorator types
        nc = CenterCalc()
        cd = LineArrowOnStart()          

        cur_thread = [[]*(self.thread_count+1) for x in xrange(self.thread_count+1)]
        cur_num = 0
        for x in A.nodes_iter():
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
        
    def populateTraceTable(self):
        """
        Method for populating the taints table
        """
        f=open(self.trace_fname, 'r')
        # read input file line by line
        trace_nodes = []
        for line in f:
            #Hard implementation of 'E' search
            if line.startswith('E'):
                trace_nodes.append(line)
                #splitted = line.split(' ')
                #self.node_ea[splitted[5]] = splitted[1]
        f.close()
        self.trace_table.setSortingEnabled(False)
        self.trace_header_labels = ["EA", "2", "3", "4", "5", "6"]
        self.trace_table.clear()
        self.trace_table.setColumnCount(len(self.trace_header_labels))
        self.trace_table.setHorizontalHeaderLabels(self.trace_header_labels)
        self.trace_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.trace_table.resizeColumnsToContents()
        self.trace_table.setSortingEnabled(True)
        self.trace_table.setRowCount(len(trace_nodes))
        self.trace_table.setContextMenuPolicy(self.QtCore.Qt.CustomContextMenu)
        self.trace_table.customContextMenuRequested.connect(self.handleTraceMenu)
        for row, ynode in enumerate(trace_nodes):
            splitted = ynode.split(' ')
            for column, column_name in enumerate(self.trace_header_labels):
                ##@self.process_header_labels = ["UUID", "Type", "Name", "StartInd", "EndInd", "Edge Anno", "Child C", "Child D"]
                if column == 0:
                    tmp_item = self.QtGui.QTableWidgetItem(splitted[1])
                elif column == 1:
                    tmp_item = self.QtGui.QTableWidgetItem(splitted[2])
                elif column == 2:
                    tmp_item = self.QtGui.QTableWidgetItem(splitted[3])
                elif column == 3:
                    tmp_item = self.QtGui.QTableWidgetItem(splitted[4])
                elif column == 4:
                    tmp_item = self.QtGui.QTableWidgetItem(splitted[5])
                elif column == 5:
                    tmp_item = self.QtGui.QTableWidgetItem(''.join(splitted[6:]))
                tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
                self.trace_table.setItem(row, column, tmp_item)
            self.trace_table.resizeRowToContents(row)
        self.trace_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.trace_table.resizeColumnsToContents()
        self.trace_table.setSortingEnabled(True)
        
    def populateTaintsTableImported(self):
        """
        Method for populating the taints table
        """
        self.taint_table.setRowCount(len(self.t_graph))
        self.taint_table.setContextMenuPolicy(self.QtCore.Qt.CustomContextMenu)
        self.taint_table.customContextMenuRequested.connect(self.handleTaintMenu)
        if self.policy == "TAINT_BRANCH":
            for row, ynode in enumerate(self.t_graph.nodes(data=True)):
                for column, column_name in enumerate(self.taints_header_labels):
                    tmp_item = None
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
                    self.taint_table.setItem(row, column, tmp_item)
                self.taint_table.resizeRowToContents(row)
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
        
    def handleTraceMenu(self, pos):
        menu = self.QtGui.QMenu()
        addr = self.QtGui.QAction("Mark Taint", menu)
        addr.setStatusTip("Mark Taint")
        menu.addAction(addr)
        self.connect(addr, self.QtCore.SIGNAL('triggered()'), self.markTaint)
        addr = self.QtGui.QAction("Splice Start", menu)
        addr.setStatusTip("Mark Splice Start")
        self.connect(addr, self.QtCore.SIGNAL('triggered()'), self.addrGo)
        menu.addAction(addr)
        addr = self.QtGui.QAction("Splice End", menu)
        addr.setStatusTip("Mark Splice End")
        self.connect(addr, self.QtCore.SIGNAL('triggered()'), self.addrGo)
        menu.addAction(addr)
        menu.exec_(self.QtGui.QCursor.pos())
        
    def markTaint(self):
        self.trace_table.currentItem().row()
        
    def addrGo(self):
        from idc import *
        uuid = self.taint_table.item(self.taint_table.currentItem().row(), 0).text()
        int_addr = self.t_graph.node[uuid]['inode'].ea
        bLoaded = isLoaded(int_addr)
        if bLoaded:
          print "Found addr: 0x%x" % int_addr
          idc.MakeCode(int_addr)
          idc.Jump(int_addr)
        #self.filters_filename_table.insertRow(self.filters_filename_table.rowCount())
        #self.filters_filename_table.setItem(self.filters_filename_table.rowCount()-1, 0, self.QtGui.QTableWidgetItem(" "))