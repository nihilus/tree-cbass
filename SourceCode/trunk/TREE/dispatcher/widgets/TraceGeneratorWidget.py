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
        tracer_icon_path = self.parent.iconPath+ "trace.png"
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
        config_info_label = QtGui.QLabel("Configurable Parameters")
        process_info_label = QtGui.QLabel("Proces Information")
        
        self._createToolbar()
        
        trace_layout = QtGui.QVBoxLayout()
        
        cb = QtGui.QCheckBox('Show title', self)
        cb.move(20, 20)
        cb.toggle()

        proc_info_widget = QtGui.QWidget()
        proc_info_layout = QtGui.QVBoxLayout()
        proc_info_layout.addWidget(cb)
        proc_info_widget.setLayout(proc_info_layout)

        config_info_widget = QtGui.QWidget()
        config_info_layout = QtGui.QVBoxLayout()
        config_info_widget.setLayout(config_info_layout)
        
        splitter = self.QtGui.QSplitter(self.QtCore.Qt.Vertical)
        q_clean_style = QtGui.QStyleFactory.create('Plastique')
        splitter.setStyle(q_clean_style)
        splitter.addWidget(process_info_label)
        splitter.addWidget(proc_info_widget)
        splitter.addWidget(config_info_label)
        splitter.addWidget(config_info_widget)
        trace_layout.addWidget(splitter)
        
        self.central_widget.setLayout(trace_layout)

        
    def _createToolbar(self):
        """
        Create the toolbar
        """

        self._createGenerateTraceAction() 
        self._createSaveConfigAction() 
        self.toolbar = self.addToolBar('Trace Generation Toolbar')
        self.toolbar.addAction(self.saveConfigAction)
        self.toolbar.addAction(self.generateTraceAction)
        
    def _createGenerateTraceAction(self):
        """
        Create that action that performs the trace
        """
        from PySide import QtGui
        from PySide.QtGui import QIcon
        
        self.generateTraceAction = QtGui.QAction(QIcon(self.parent.iconPath + "trace.png"), "Generate the trace.", self)
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
        
        self.saveConfigAction = QtGui.QAction(QIcon(self.parent.iconPath + "save.png"), "Sasve config", self)
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
