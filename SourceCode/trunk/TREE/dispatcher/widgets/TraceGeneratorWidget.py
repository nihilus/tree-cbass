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
        from PySide import QtGui, QtCore
        self._createToolbar()
        self.filters_qb = QtGui.QGroupBox(self.central_widget)
        self.filters_qb.setGeometry(QtCore.QRect(10, 200, 511, 191))
        self.filters_qb.setObjectName("filters_qb")
        self.gridLayoutWidget_2 = QtGui.QWidget(self.filters_qb)
        self.gridLayoutWidget_2.setGeometry(QtCore.QRect(10, 20, 491, 161))
        self.gridLayoutWidget_2.setObjectName("gridLayoutWidget_2")
        self.gridLayout_2 = QtGui.QGridLayout(self.gridLayoutWidget_2)
        #self.gridLayout_2.setMargin(0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.verticalLayout_3 = QtGui.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.filename_label = QtGui.QLabel(self.gridLayoutWidget_2)
        self.filename_label.setObjectName("filename_label")
        self.verticalLayout_3.addWidget(self.filename_label)
        self.filters_filename_table = QtGui.QTableView(self.gridLayoutWidget_2)
        self.filters_filename_table.setObjectName("filters_filename_table")
        self.verticalLayout_3.addWidget(self.filters_filename_table)
        self.gridLayout_2.addLayout(self.verticalLayout_3, 0, 0, 1, 1)
        self.verticalLayout_4 = QtGui.QVBoxLayout()
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.network_port_label = QtGui.QLabel(self.gridLayoutWidget_2)
        self.network_port_label.setObjectName("network_port_label")
        self.verticalLayout_4.addWidget(self.network_port_label)
        self.filters_network_port_table = QtGui.QTableView(self.gridLayoutWidget_2)
        self.filters_network_port_table.setObjectName("filters_network_port_table")
        self.verticalLayout_4.addWidget(self.filters_network_port_table)
        self.gridLayout_2.addLayout(self.verticalLayout_4, 0, 1, 1, 1)
        self.process_qbox = QtGui.QGroupBox(self.central_widget)
        self.process_qbox.setGeometry(QtCore.QRect(10, 10, 511, 51))
        self.process_qbox.setObjectName("process_qbox")
        self.layoutWidget = QtGui.QWidget(self.process_qbox)
        self.layoutWidget.setGeometry(QtCore.QRect(10, 14, 411, 22))
        self.layoutWidget.setObjectName("layoutWidget")
        self.horizontalLayout_8 = QtGui.QHBoxLayout(self.layoutWidget)
        #self.horizontalLayout_8.setMargin(0)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.name_label = QtGui.QLabel(self.layoutWidget)
        self.name_label.setObjectName("name_label")
        self.horizontalLayout_8.addWidget(self.name_label)
        self.name_label_d = QtGui.QLabel(self.layoutWidget)
        self.name_label_d.setObjectName("name_label_d")
        self.horizontalLayout_8.addWidget(self.name_label_d)
        self.os_label = QtGui.QLabel(self.layoutWidget)
        self.os_label.setObjectName("os_label")
        self.horizontalLayout_8.addWidget(self.os_label)
        self.os_label_d = QtGui.QLabel(self.layoutWidget)
        self.os_label_d.setObjectName("os_label_d")
        self.horizontalLayout_8.addWidget(self.os_label_d)
        self.params_qbox = QtGui.QGroupBox(self.central_widget)
        self.params_qbox.setGeometry(QtCore.QRect(10, 60, 511, 121))
        self.params_qbox.setObjectName("params_qbox")
        self.gridLayoutWidget_3 = QtGui.QWidget(self.params_qbox)
        self.gridLayoutWidget_3.setGeometry(QtCore.QRect(9, 15, 501, 103))
        self.gridLayoutWidget_3.setObjectName("gridLayoutWidget_3")
        self.gridLayout_3 = QtGui.QGridLayout(self.gridLayoutWidget_3)
        #self.gridLayout_3.setMargin(0)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.horizontalLayout_6 = QtGui.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.host_label = QtGui.QLabel(self.gridLayoutWidget_3)
        self.host_label.setObjectName("host_label")
        self.horizontalLayout_6.addWidget(self.host_label)
        self.host_label_edit = QtGui.QLineEdit(self.gridLayoutWidget_3)
        self.host_label_edit.setObjectName("host_label_edit")
        self.horizontalLayout_6.addWidget(self.host_label_edit)
        self.password_label = QtGui.QLabel(self.gridLayoutWidget_3)
        self.password_label.setObjectName("password_label")
        self.horizontalLayout_6.addWidget(self.password_label)
        self.password_label_edit = QtGui.QLineEdit(self.gridLayoutWidget_3)
        self.password_label_edit.setObjectName("password_label_edit")
        self.horizontalLayout_6.addWidget(self.password_label_edit)
        self.port_label = QtGui.QLabel(self.gridLayoutWidget_3)
        self.port_label.setObjectName("port_label")
        self.horizontalLayout_6.addWidget(self.port_label)
        self.port_label_edit = QtGui.QLineEdit(self.gridLayoutWidget_3)
        self.port_label_edit.setObjectName("port_label_edit")
        self.horizontalLayout_6.addWidget(self.port_label_edit)
        self.gridLayout_3.addLayout(self.horizontalLayout_6, 2, 0, 1, 1)
        self.remote_cb = QtGui.QCheckBox(self.gridLayoutWidget_3)
        self.remote_cb.setObjectName("remote_cb")
        self.gridLayout_3.addWidget(self.remote_cb, 1, 0, 1, 1)
        self.horizontalLayout_7 = QtGui.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.verticalLayout_5 = QtGui.QVBoxLayout()
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.path_label = QtGui.QLabel(self.gridLayoutWidget_3)
        self.path_label.setObjectName("path_label")
        self.verticalLayout_5.addWidget(self.path_label)
        self.arguments_label = QtGui.QLabel(self.gridLayoutWidget_3)
        self.arguments_label.setObjectName("arguments_label")
        self.verticalLayout_5.addWidget(self.arguments_label)
        self.horizontalLayout_7.addLayout(self.verticalLayout_5)
        self.verticalLayout_6 = QtGui.QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.path_edit = QtGui.QLineEdit(self.gridLayoutWidget_3)
        self.path_edit.setObjectName("path_edit")
        self.verticalLayout_6.addWidget(self.path_edit)
        self.arguments_edit = QtGui.QLineEdit(self.gridLayoutWidget_3)
        self.arguments_edit.setObjectName("arguments_edit")
        self.verticalLayout_6.addWidget(self.arguments_edit)
        self.horizontalLayout_7.addLayout(self.verticalLayout_6)
        self.gridLayout_3.addLayout(self.horizontalLayout_7, 0, 0, 1, 1)
        self.retranslateUi()
        
    def retranslateUi(self):
        self.filters_qb.setTitle("Filters")
        self.filename_label.setText("File Name:")
        self.network_port_label.setText("Network Port:")
        self.process_qbox.setTitle("Process Information")
        self.name_label.setText("Name:")
        self.name_label_d.setText("blank")
        self.os_label.setText("OS:")
        self.os_label_d.setText("blank")
        self.params_qbox.setTitle("Configurable Parameters")
        self.host_label.setText("Host:     ")
        self.password_label.setText("Password:    ")
        self.port_label.setText("Port     ")
        self.remote_cb.setText("Remote")
        self.path_label.setText("Path:")
        self.arguments_label.setText("Arguments:    ")
        
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
