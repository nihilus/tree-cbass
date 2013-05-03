from PySide.QtGui import QMainWindow 
from PySide import QtGui, QtCore
#from PySide.QtGui import QIcon
class TraceGeneratorWidget(QMainWindow):
    """
    This widget is the front-end for the trace generations.
    """
    def __init__(self,parent,funcCallbacks):
        #from PySide import QtGui, QtCore
        
        from ..core.DebugPrint import dbgPrint, Print

        from ..core.structures.Tracer import IDATrace
        from ..core.structures.Tracer.Config.config import ProcessConfig as ProcessConfig
        
        QtGui.QMainWindow.__init__(self)
        Print( "[|] loading TraceGenerationWidget" )
        # Access to shared modules
       
        self.idaTracer = IDATrace(funcCallbacks)
        self.processConfig = ProcessConfig()
        self.parent = parent
        self.name = "Trace Generation"
        tracer_icon_path = self.parent.iconPath+ "trace.png"
        self.icon = QtGui.QIcon(tracer_icon_path)
        
        #References to qt-specific modules
        self.QtGui = QtGui
        self.QtCore = QtCore
        self.central_widget = self.QtGui.QWidget()
        self.setCentralWidget(self.central_widget)
        self._createGui()
        self.populateConfig()
        
    def _createGui(self):
        """
        Create the main GUI with its components
        """
        # Create buttons
        #from PySide import QtGui, QtCore
        #self.setWindowTitle("Hello")
        self._createToolbar()
        trace_layout = QtGui.QVBoxLayout()
        self.filters_qb = QtGui.QGroupBox()
        #self.filters_qb.setGeometry(QtCore.QRect(10, 10, 500, 300))
        self.filters_qb.setObjectName("filters_qb")
        self.gridLayoutWidget_2 = QtGui.QWidget(self.filters_qb)
        self.gridLayoutWidget_2.setGeometry(QtCore.QRect(10, 10, 500, 300))
        self.gridLayoutWidget_2.setObjectName("gridLayoutWidget_2")
        self.gridLayout_2 = QtGui.QGridLayout(self.gridLayoutWidget_2)
        #self.gridLayout_2.setMargin(0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.verticalLayout_3 = QtGui.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.filename_label = QtGui.QLabel(self.gridLayoutWidget_2)
        self.filename_label.setObjectName("filename_label")
        self.verticalLayout_3.addWidget(self.filename_label)
        self.filters_filename_table = QtGui.QTableWidget(self.gridLayoutWidget_2)
        self.filters_filename_table.setObjectName("filters_filename_table")
        self.verticalLayout_3.addWidget(self.filters_filename_table)
        self.gridLayout_2.addLayout(self.verticalLayout_3, 0, 0, 1, 1)
        self.verticalLayout_4 = QtGui.QVBoxLayout()
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.network_port_label = QtGui.QLabel(self.gridLayoutWidget_2)
        self.network_port_label.setObjectName("network_port_label")
        self.verticalLayout_4.addWidget(self.network_port_label)
        self.filters_network_port_table = QtGui.QTableWidget(self.gridLayoutWidget_2)
        self.filters_network_port_table.setObjectName("filters_network_port_table")
        self.verticalLayout_4.addWidget(self.filters_network_port_table)
        self.gridLayout_2.addLayout(self.verticalLayout_4, 0, 1, 1, 1)
        self.process_qbox = QtGui.QGroupBox()
        #self.process_qbox.setGeometry(QtCore.QRect(10, 10, 511, 15))
        self.process_qbox.setObjectName("process_qbox")
        self.layoutWidget = QtGui.QWidget(self.process_qbox)
        self.layoutWidget.setGeometry(QtCore.QRect(10, 10, 400, 30))
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
        self.params_qbox = QtGui.QGroupBox()
        #self.params_qbox.setGeometry(QtCore.QRect(10, 10, 500, 300))
        self.params_qbox.setObjectName("params_qbox")
        self.gridLayoutWidget_3 = QtGui.QWidget(self.params_qbox)
        self.gridLayoutWidget_3.setGeometry(QtCore.QRect(10, 10, 500, 300))
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
        self.host_label_edit.setInputMask("000.000.000.000;_");
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
        self.port_label_edit.setInputMask("00000");
        self.port_label_edit.setObjectName("port_label_edit")
        self.horizontalLayout_6.addWidget(self.port_label_edit)
        self.gridLayout_3.addLayout(self.horizontalLayout_6, 2, 0, 1, 1)
        self.remote_cb = QtGui.QCheckBox(self.gridLayoutWidget_3)
        self.remote_cb.setObjectName("remote_cb")
        self.remote_cb.stateChanged.connect(self.remote_cbStateChanged)
        
        self.gridLayout_3.addWidget(self.remote_cb, 1, 0, 1, 1)
        self.horizontalLayout_7 = QtGui.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.verticalLayout_5 = QtGui.QVBoxLayout()
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.application_label = QtGui.QLabel(self.gridLayoutWidget_3)
        self.application_label.setObjectName("applicationlabel")
        self.verticalLayout_5.addWidget(self.application_label)
        self.path_label = QtGui.QLabel(self.gridLayoutWidget_3)
        self.path_label.setObjectName("path_label")
        self.verticalLayout_5.addWidget(self.path_label)
        self.arguments_label = QtGui.QLabel(self.gridLayoutWidget_3)
        self.arguments_label.setObjectName("arguments_label")
        self.verticalLayout_5.addWidget(self.arguments_label)
        self.horizontalLayout_7.addLayout(self.verticalLayout_5)
        self.verticalLayout_6 = QtGui.QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.application_edit = QtGui.QLineEdit(self.gridLayoutWidget_3)
        self.application_edit.setObjectName("application_edit")
        self.verticalLayout_6.addWidget(self.application_edit)
        self.path_edit = QtGui.QLineEdit(self.gridLayoutWidget_3)
        self.path_edit.setObjectName("path_edit")
        self.verticalLayout_6.addWidget(self.path_edit)
        self.arguments_edit = QtGui.QLineEdit(self.gridLayoutWidget_3)
        self.arguments_edit.setObjectName("arguments_edit")
        self.verticalLayout_6.addWidget(self.arguments_edit)
        self.horizontalLayout_7.addLayout(self.verticalLayout_6)
        self.gridLayout_3.addLayout(self.horizontalLayout_7, 0, 0, 1, 1)
        self.retranslateUi()
        
        splitter1 = QtGui.QSplitter(QtCore.Qt.Horizontal)
        splitter1.addWidget(self.params_qbox)
        splitter1.addWidget(self.filters_qb)
        valueList1 = [5,95]
        splitter1.setSizes(valueList1)

        splitter2 = QtGui.QSplitter(QtCore.Qt.Vertical)
        splitter2.addWidget(splitter1)
        splitter2.addWidget(self.process_qbox)
        valueList2 = [80,20]
        splitter2.setSizes(valueList2)
        
        trace_layout.addWidget(splitter2)
        self.central_widget.setLayout(trace_layout)
        
    def retranslateUi(self):
        self.filters_qb.setTitle("Filters")
        self.filename_label.setText("File Name:")
        self.network_port_label.setText("Network Port:")
        self.process_qbox.setTitle("Process Information")
        self.name_label.setText("Name:")
        self.name_label_d.setText("blank")
        self.application_label.setText("Application:    ")
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
        #from PySide.QtGui import QIcon
        self.generateTraceAction = QtGui.QAction(QtGui.QIcon(self.parent.iconPath + "trace.png"), "Generate the trace.", self)
        self.generateTraceAction.triggered.connect(self.onGenerateTraceButtonClicked)
        
    def onGenerateTraceButtonClicked(self):
        """
        Action for calling the trace functionality 
        """
        
        #start debugging
        self.getConfigFromGUI()
        self.idaTracer.run(self.processConfig)
  
    def _createSaveConfigAction(self):
        """
        Save config
        """
        #from PySide.QtGui import QIcon
        self.saveConfigAction = QtGui.QAction(QtGui.QIcon(self.parent.iconPath + "save.png"), "Save config", self)
        self.saveConfigAction.triggered.connect(self.onSaveConfigButtonClicked)
  
    def getConfigFromGUI(self):
        """
        Action for saving config
        """
        from ..core.DebugPrint import dbgPrint, Print
         
        #Get all the process config data from the GUI
        self.processConfig.application = str(self.application_edit.text())
        self.processConfig.path = str(self.path_edit.text())
        self.processConfig.args = str(self.arguments_edit.text())
        self.processConfig.host = str(self.host_label_edit.text())
        self.processConfig._pass = str(self.password_label_edit.text())
        self.processConfig.port = str(self.port_label_edit.text())
        #Hardcoded debugger until we integrate kernel trace
        #self.processConfig.debugger = 
        if self.remote_cb.isChecked():
            self.processConfig.remote = "True"
        else:
            self.processConfig.remote = "False"
            
        tempFileFilter = []
        for row in range(self.filters_filename_table.rowCount()):
            data = self.filters_filename_table.item(row, 0).text()
            Print( "Adding file %s" % data )
            tempFileFilter.append(data)
            
        if len(tempFileFilter) > 0:
            self.processConfig.fileFilter = tempFileFilter
        else:
            self.processConfig.fileFilter = None
            
        tempNetworkFilter = []
        
        for row in range(self.filters_network_port_table.rowCount()):
            data = self.filters_network_port_table.item(row, 0).text()
            Print( "Adding port %s" % data )
            tempNetworkFilter.append(data)

        if len(tempNetworkFilter) > 0:
            self.processConfig.networkFilter = tempNetworkFilter
        else:
            self.processConfig.networkFilter = None
            
    def onSaveConfigButtonClicked(self):
        """
        Action for saving config
        """
        #start debugging
        from dispatcher.core.structures.Tracer.Config.config import ProcessConfig as ProcessConfig
        
        self.getConfigFromGUI()
        self.idaTracer.setProcessConfig(self.processConfig)
        
    def populateConfig(self):
        from ..core.DebugPrint import dbgPrint, Print
        
        self.processConfig = self.idaTracer.getProcessConfig()
        if self.processConfig is None:
            Print( "Error, we need to add a new config" )
            Print( "Should not get here!!!" )
        else:
            self.application_edit.setText(self.processConfig.getApplication())
            self.path_edit.setText(self.processConfig.getPath())
            self.name_label_d.setText(self.processConfig.getName())
            self.os_label_d.setText(self.processConfig.getOsType() + " " + self.processConfig.getOsArch() + " Bit")
            self.arguments_edit.setText(self.processConfig.getArgs())
            #sdir  = self.processConfig.getSdir()
            self.host_label_edit.setText(self.processConfig.getHost())
            self.password_label_edit.setText(self.processConfig.getPass())
            #_debugger = self.processConfig.getDebugger()
 
            #port  = int(self.processConfig.getPort())
            self.port_label_edit.setText(self.processConfig.getPort())
            if self.processConfig.getRemote()=="True":
                self.remote_cb.setCheckState(self.QtCore.Qt.Checked)
                self.host_label_edit.setEnabled(1)
                self.password_label_edit.setEnabled(1)
                self.port_label_edit.setEnabled(1)
            else:
                self.remote_cb.setCheckState(self.QtCore.Qt.Unchecked)
                self.host_label_edit.setDisabled(1)
                self.password_label_edit.setDisabled(1)
                self.port_label_edit.setDisabled(1)
            
            self.filters = dict()
            
            fileFilter = self.processConfig.getFileFilter()
            if fileFilter is not None:
                #self.filters['file'] = fileFilter
                Print( "Found %d file filters" % len(fileFilter) )
                self.populateFiltersTable(fileFilter, self.filters_filename_table)
            else:
                Print( "No file filters found" )
                
            networkFilter = self.processConfig.getNetworkFilter()
            if networkFilter is not None:
                #self.filters['network'] = networkFilter
                Print( "Found %d network filters" % len(networkFilter) )
                self.populateFiltersTable(networkFilter, self.filters_network_port_table)
            else:
                Print( "No network filters found" )

    def populateFiltersTable(self, _filter, filter_table):
        table_header_labels = ["Value"]
        filter_table.clear()
        filter_table.setColumnCount(len(table_header_labels))
        filter_table.setHorizontalHeaderLabels(table_header_labels)
        filter_table.setRowCount(len(_filter))
        filter_table.setContextMenuPolicy(self.QtCore.Qt.CustomContextMenu)
        if filter_table.objectName() == "filters_filename_table":
            filter_table.customContextMenuRequested.connect(self.handleFileFilterMenu)
        elif filter_table.objectName() == "filters_network_port_table":
            filter_table.customContextMenuRequested.connect(self.handleNetworkFilterMenu)
        for row, node in enumerate(_filter):
            tmp_item = self.QtGui.QTableWidgetItem(node)
            tmp_item.setFlags(tmp_item.flags() & ~self.QtCore.Qt.ItemIsEditable)
            filter_table.setItem(row, 0, tmp_item)
            filter_table.resizeRowToContents(row)
        filter_table.setSelectionMode(self.QtGui.QAbstractItemView.SingleSelection)
        filter_table.resizeColumnsToContents()
        filter_table.setSortingEnabled(True)
        
    def handleFileFilterMenu(self, pos):
        menu = self.QtGui.QMenu()
        add = self.QtGui.QAction("Add", menu)
        add.setStatusTip("Add a filter")
        self.connect(add, self.QtCore.SIGNAL('triggered()'), self.addFileFilter)
        menu.addAction(add)
        delete  = self.QtGui.QAction("Delete", menu)
        delete.setStatusTip("Delete a filter")
        self.connect(delete, self.QtCore.SIGNAL('triggered()'), self.delFileFilter)
        menu.addAction(delete)
        menu.exec_(self.QtGui.QCursor.pos())
        
    def handleNetworkFilterMenu(self, pos):
        menu = self.QtGui.QMenu()
        add = self.QtGui.QAction("Add", menu)
        add.setStatusTip("Add a filter")
        self.connect(add, self.QtCore.SIGNAL('triggered()'), self.addNetworkFilter)
        menu.addAction(add)
        delete  = self.QtGui.QAction("Delete", menu)
        delete.setStatusTip("Delete a filter")
        self.connect(delete, self.QtCore.SIGNAL('triggered()'), self.delNetworkFilter)
        menu.addAction(delete)
        menu.exec_(self.QtGui.QCursor.pos())
        
    def addFileFilter(self):
        self.filters_filename_table.insertRow(self.filters_filename_table.rowCount())
        self.filters_filename_table.setItem(self.filters_filename_table.rowCount()-1, 0, self.QtGui.QTableWidgetItem(" "))
        
    def delFileFilter(self):
        self.filters_filename_table.removeRow(self.filters_filename_table.currentItem().row())
        
    def addNetworkFilter(self):
        self.filters_network_port_table.insertRow(self.filters_network_port_table.rowCount())
        self.filters_network_port_table.setItem(self.filters_network_port_table.rowCount()-1, 0, self.QtGui.QTableWidgetItem(" "))
        
    def delNetworkFilter(self):
        self.filters_network_port_table.removeRow(self.filters_network_port_table.currentItem().row())
        
    def remote_cbStateChanged(self,state):
        if state == self.QtCore.Qt.Checked:
            self.host_label_edit.setEnabled(1)
            self.password_label_edit.setEnabled(1)
            self.port_label_edit.setEnabled(1)
        else:
            self.host_label_edit.setDisabled(1)
            self.password_label_edit.setDisabled(1)
            self.port_label_edit.setDisabled(1)