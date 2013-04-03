from PySide import QtGui, QtCore
from PySide.QtGui import QIcon

class TraceGeneratorWidget(QtGui.QMainWindow):
    """
    This widget is the front-end for the trace generations.
    """
    def __init__(self,parent,funcCallbacks):
        from PySide import QtGui, QtCore
        from PySide.QtGui import QIcon

        import dispatcher.core.structures.Tracer.IDATrace as IDATrace

        QtGui.QMainWindow.__init__(self)
        print "[|] loading TraceGenerationWidget"
        # Access to shared modules
       
        self.idaTracer = IDATrace(funcCallbacks)
        self.parent = parent
        self.name = "Trace Generation"
        tracer_icon_path = self.parent.config.icon_file_path + "trace.png"
        self.icon = QIcon(tracer_icon_path)
        
        #References to qt-specific modules
        self.QtGui = QtGui
        self.QtCore = QtCore
        self.central_widget = self.QtGui.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()
        
    def _createGui(self):
        """
        Create the main GUI with its components
        """
        # Create buttons
        from PySide import QtGui
        self.processes_label = QtGui.QLabel("Processes (0/0)")
        self.active_process_label = QtGui.QLabel("Selected Process:")
        self.trace_nodes_label = QtGui.QLabel("Trace Nodes(0/0)")
        
        self._createToolbar()
        
        self._createProcessTable()
        self._createDetailsTable() #create detailst able
        self._createTraceTable()
        
        trace_layout = QtGui.QVBoxLayout()
        trace_info_widget = QtGui.QWidget()
        trace_info_layout = QtGui.QHBoxLayout()
        trace_info_layout.addWidget(self.trace_nodes_label)
        trace_info_widget.setLayout(trace_info_layout)
        
        upper_table_widget = QtGui.QWidget()
        upper_table_layout = QtGui.QVBoxLayout()
        upper_table_layout.addWidget(trace_info_widget)
        upper_table_layout.addWidget(self.trace_table)
        upper_table_widget.setLayout(upper_table_layout)
        
        process_info_widget = QtGui.QWidget()
        process_info_layout = QtGui.QHBoxLayout()
        #self.process_active_only_cb = QtGui.QCheckBox("Only active processes")
        process_info_layout.addWidget(self.processes_label)
        #process_info_layout.addWidget(self.process_table)
        process_info_widget.setLayout(process_info_layout)
        
        details_widget = QtGui.QWidget()
        details_layout = QtGui.QHBoxLayout()
        details_layout.addWidget(self.process_table)
        details_layout.addWidget(self.details_table)
        details_widget.setLayout(details_layout)
        
        lower_tables_widget = QtGui.QWidget()
        lower_tables_layout = QtGui.QVBoxLayout()
        lower_tables_layout.addWidget(process_info_widget)
        lower_tables_layout.addWidget(details_widget)
        lower_tables_widget.setLayout(lower_tables_layout)
        
        splitter = self.QtGui.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = QtGui.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(upper_table_widget)
        splitter.addWidget(lower_tables_widget)
        trace_layout.addWidget(splitter)
        
        self.central_widget.setLayout(trace_layout)
        self.populateProcessTable()
        self.populateTraceTable()
        
    def _createToolbar(self):
        """
        Create the toolbar
        """
        self._createImportConfigAction()
        self._createImportTraceAction()
        self._createGenerateTraceAction() 
        self._createSaveConfigAction() 
        self.toolbar = self.addToolBar('Trace Generation Toolbar')
        self.toolbar.addAction(self.importConfigAction)
        self.toolbar.addAction(self.importTraceAction)
        self.toolbar.addAction(self.saveConfigAction)
        self.toolbar.addAction(self.generateTraceAction)
        
    def _createImportConfigAction(self):
        """
        Create the import config action
        """
        from PySide import QtGui
        from PySide.QtGui import QIcon
        self.importConfigAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path +
        "import2.png"),
            "Import the XML config", self)
        self.importConfigAction.triggered.connect(self.onImportConfigButtonClicked)
        
    def onImportConfigButtonClicked(self):
        """
        Action for importing an XML file containing VM information
        """
        from dispatcher.trace_config import TraceConfig
        fname, _ = self.QtGui.QFileDialog.getOpenFileName(self, 'Import Config')
        self.t_config_fname = fname
        self.t_config = TraceConfig(fname)
        print self.t_config
        self.populateProcessTable()
        
    def _createImportTraceAction(self):
        """
        Create the import trace action
        """
        from PySide import QtGui
        from PySide.QtGui import QIcon
        self.importTraceAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path +
        "import.png"),
            "Import the trace file", self)
        self.importTraceAction.triggered.connect(self.onImportTraceButtonClicked)
        
    def onImportTraceButtonClicked(self):
        """ 
        Action for importing an Trace file and populate table
        """
        from dispatcher.core.structures.Parse import TrNode
        fname, _ = self.QtGui.QFileDialog.getOpenFileName(self, 'Import Trace')
        self.trace_fname = fname
        
    def _createGenerateTraceAction(self):
        """
        Create that action that performs the trace
        """
        from PySide import QtGui
        from PySide.QtGui import QIcon
        
        self.generateTraceAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + "trace.png"), "Generate the trace.", self)
        self.generateTraceAction.triggered.connect(self.onGenerateTraceButtonClicked)
        
    def onGenerateTraceButtonClicked(self):
        """
        Action for calling the trace functionality 
        """
        
        #start debugging

        self.idaTracer.run()
  
    def _createSaveConfigAction(self):
        """
        Save config
        """
        from PySide import QtGui
        from PySide.QtGui import QIcon
        
        self.saveConfigAction = QtGui.QAction(QIcon(self.parent.config.icon_file_path + "save.png"), "Sasve config", self)
        self.saveConfigAction.triggered.connect(self.onSaveConfigButtonClicked)
  
        
    def onSaveConfigButtonClicked(self):
        """
        Action for saving config
        """
        
        #start debugging

        
        
    def _createTraceTable(self):
        """
        Create the top table used for showing all
        """
        self.trace_table = self.QtGui.QTableWidget()
        #self.trace_table.clicked.connect(self.onTraceClicked)
        self.trace_table.doubleClicked.connect(self.onTraceDoubleClicked)
        
    def _createProcessTable(self):
        """
        Create the top table used for showing all
        """
        self.process_table = self.QtGui.QTableWidget()
        self.process_table.clicked.connect(self.onProcessClicked)
        
    def _createDetailsTable(self):
        """
        Create the bottom left table
        """
        self.details_table = self.QtGui.QTableWidget()
        
    def onTraceDoubleClicked(self, mi):
        """
        if a trace cell is double clicked
        """
        self.double_clicked_trace = self.trace_table.item(mi.row(), 1).text()
        self.trace_table.item(mi.row(), 1).setBackgroundColor(QColor(QtCore.red))
    
    def onProcessClicked(self, mi):
        """
        If a process is clicked, the view of the process and details are updated
        """
        self.clicked_process = self.process_table.item(mi.row(), 1).text()
        self.populateDetailsTable(self.clicked_process)
        
    def populateDetailsTable(self, process_c):
        """
        Populate the details table based on the selected process in the process table.
        For no uneditable
        @Todo:
            Make editable and have changes pushed out to file
        """
        from dispatcher.trace_config import TraceConfig
        self.details_table.setSortingEnabled(False)
        self.details_header_labels = ["node", "node value"]
        self.details_table.clear()
        self.details_table.setColumnCount(len(self.details_header_labels))
        self.details_table.setHorizontalHeaderLabels(self.details_header_labels)
        cur_config = TraceConfig(self.t_config_fname)
        cur_config.setProcess(process_c)
        #Account for if a member is a list and recurse the elements
        mem_inc = 0
        members = cur_config.getMembers()
        self.details_table.setRowCount(cur_config.getMemberCount())
        for row, member in enumerate(members):
            if type(getattr(cur_config, member)) is list:
                for item in getattr(cur_config, member):
                    tmp_item = self.QtGui.QTableWidgetItem(member)
                    self.details_table.setItem(row+mem_inc,0,tmp_item)
                    tmp_item = self.QtGui.QTableWidgetItem(item)
                    self.details_table.setItem(row+mem_inc,1,tmp_item)
                    self.details_table.resizeRowToContents(row+mem_inc)
                    mem_inc = mem_inc + 1
            else:
                tmp_item = self.QtGui.QTableWidgetItem(member)
                self.details_table.setItem(row+mem_inc,0,tmp_item)
                tmp_item = self.QtGui.QTableWidgetItem(getattr(cur_config, member))
                self.details_table.setItem(row+mem_inc,1,tmp_item)
                self.details_table.resizeRowToContents(row+mem_inc)
        self.details_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        self.details_table.resizeColumnsToContents()
        self.details_table.setSortingEnabled(True)
        
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
                    tmp_item.setFlags(tmp_item.flags() & self.QtCore.Qt.ItemIsEditable)
                    self.trace_table.setItem(row, column, tmp_item)
                self.trace_table.resizeRowToContents(row)
            self.trace_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.trace_table.resizeColumnsToContents()
            self.trace_table.setSortingEnabled(True)
        else:
            self.trace_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.trace_table.resizeColumnsToContents()
            
    def populateProcessTable(self):
        """
        Populate the VM table with information about the virtual machines
        """
        #If no config then connect to virtualbox in config
        self.process_table.setSortingEnabled(False)
        self.process_header_labels = ["Remote", "Process", "Platform"]
        self.process_table.clear()
        self.process_table.setColumnCount(len(self.process_header_labels))
        self.process_table.setHorizontalHeaderLabels(self.process_header_labels)
        if hasattr(self, 't_config'):
            processes = self.t_config.root.findall('process')
            self.process_table.setRowCount(len(processes))
            self.updateProcessesLabel(len(processes),len(processes))
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
                    self.process_table.setItem(row, column, tmp_item)
                self.process_table.resizeRowToContents(row)
            self.process_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.process_table.resizeColumnsToContents()
            self.process_table.setSortingEnabled(True)
        else:
            self.process_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
            self.process_table.resizeColumnsToContents()
            self.process_table.setSortingEnabled(True)
            
    def updateProcessesLabel(self,n1, n2):
        self.processes_label.setText("Processes (%d/%d)" %
            (n1, n2))
