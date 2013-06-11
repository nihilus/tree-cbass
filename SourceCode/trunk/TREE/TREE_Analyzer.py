#!/usr/bin/python
############################
#
#
############################
import os
import sys
import time

import idc
import idaapi
import idautils
from idaapi import PluginForm, plugin_t
from PySide import QtGui
from PySide.QtGui import QIcon

from dispatcher.widgets.AnalyzerWidget import AnalyzerWidget
from dispatcher.widgets.VisualizerWidget import VisualizerWidget

HOTKEYS = None
DISPATCHER = None
NAME = "TREE Analyzer v0.2"

class DispatcherForm(PluginForm):
    """
    This class contains the main window of TaintVisualizer QT Graph
    Setup of core modules and widgets will be performed in here
    """
    
    def __init__(self):
        super(DispatcherForm, self).__init__()
        global HOTKEYS
        HOTKEYS = []
        self.dispatcher_widgets = []
        self.idaPluginDir = os.path.join(GetIdaDirectory(),"plugins")
        
        self.iconPath = os.path.join(self.idaPluginDir ,"dispatcher","icons")
        path = os.path.join(self.iconPath ,"dispatcher.png")
        self.icon = QIcon(path)

    def setupWidgets(self):
        """
        Setup dispatcher widgets.
        """
        time_before = time.time()
        print ("[/] setting up widgets...")
        self.dispatcher_widgets.append(AnalyzerWidget(self))
        self.dispatcher_widgets.append(VisualizerWidget(self))
        self.setupDispatcherForm()
        print("[\\] this took %3.2f seconds.\n" % (time.time() - time_before))
        
    def setupDispatcherForm(self):
        """
        Organize the initialized widgets into tabs
        """
        self.tabs = QtGui.QTabWidget()
        self.tabs.setTabsClosable(False)
        for widget in self.dispatcher_widgets:
            self.tabs.addTab(widget, widget.icon, widget.name)
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.tabs)
        self.parent.setLayout(layout)
        
    def OnCreate(self, form):
        """
        When creating the form, setup the modules and widgets
        """
        self.printBanner()
        self.parent = self.FormToPySideWidget(form)
        self.parent.setWindowIcon(self.icon)
        self.setupWidgets()
        
    def printBanner(self):
        banner = "#############################################\n" \
               + " ___________________________________________ \n" \
               + " \__    ___/\______   \_   _____/\_   _____/ \n" \
               + "    |    |    |       _/|    __)_  |    __)_ \n" \
               + "    |    |    |    |   \|        \ |        \ \n" \
               + "    |____|    |____|_  /_______  //_______  / \n" \
               + "                     \/        \/         \/  \n" \
               + "#############################################\n" \
               + " Taint-enabled Reverse Engineering Environment\n" \
               + " by Battelle BIT Team                       \n" \
               + "#############################################\n"
        print banner
        print ("[+] Loading TREE Analyzer.QT")
        
    def OnClose(self, form):
        """
        Perform cleanup.
        """
        global DISPATCHER
        del DISPATCHER
        
    def Show(self):
        if idc.GetInputMD5() == None:
            return
        else:
            return PluginForm.Show(self,
                NAME,
                options=(PluginForm.FORM_CLOSE_LATER | PluginForm.FORM_RESTORE | PluginForm.FORM_SAVE))
    
 #########################################################
 # functionality for widgets
 #########################################################
 
    def setTabFocus(self, widget_name):
        """
        Can be used by Dispatcher widgets to set focus to a widget, identified by name.
        @param widget_name: A widget name
        @type widget_name: STR
        """
        for widget in self.dispatcher_widgets:
            if widget.name == widget_name:
                tab_index = self.tabs.indexOf(widget)
                self.tabs.setCurrentIndex(tab_index)
        return
        
    def registerHotkey(self, shortcut, py_function_pointer):
        """
        Used by widgets to register hotkeys.
        Global list of HOTKEYS of function pointers
        Functions cannot take parameters atm
        @param shortcut: A string describing a shortcut, e.g. "ctrl+F3"
        @type shortcut: str
        @param py_function_pointer: a python function that shall be called when the shortcut is triggered
        @type py_function_pointer: a pointer to a python function
        """
        global HOTKEYS
        hotkey_index = len(HOTKEYS)
        hotkey_name = "TREE_Analyzer_HOTKEY_%d" % hotkey_index
        HOTKEYS.append(py_function_pointer)
        #self.ida_proxy.CompileLine('static %s() { RunPythonStatement("HOTKEY[%d]()"); }' % (hotkey_name, hotkey_index))
        #self.ida_proxy.Addhotkey(shortcut, hotkey_name)
        
    def passTaintGraph(self, t, widget_name, prop_policy):
        """
        Pass the taintgraph from the analyzer to visualizer
        """
        for widget in self.dispatcher_widgets:
            if widget.name == widget_name:
                widget.setTaintGraph(t, prop_policy)
                
    def passTraceFile(self, t, widget_name):
        """
        Pass the taintgraph from the analyzer to visualizer
        """
        for widget in self.dispatcher_widgets:
            if widget.name == widget_name:
                widget.setTraceFile(t)

####################################################################
#   Plugin
####################################################################
def PLUGIN_ENTRY():
    return DispatcherPlugin()
    
class DispatcherPlugin(plugin_t):
    """
    Plugin version.
    """
    flags = idaapi.PLUGIN_UNL
    comment = NAME
    help = ""
    wanted_name = "TREE Analyzer"
    wanted_hotkey = "Ctrl-F4"
    
    def init(self):
        self.icon_id = 0
        return idaapi.PLUGIN_OK
        
    def run(self, arg=0):
        f = DispatcherForm()
        f.Show()
        return
        
    def term(self):
        pass
####################################################################
#   Script usage
####################################################################

def main():

    global DISPATCHER
    try:
        DISPATCHER
        DISPATCHER.OnClose(DISPATCHER)
        print ("reloading Dispatcher")
        DISPATCHER = DispatcherForm()
        return
    except Exception:
        DISPATCHER = DispatcherForm()
    """    
    if DISPATCHER.config.dispatcher_plugin_only:
        print "Dispatcher: configured as plugin-only mode, ignoring main function of script. " \
            + "This can be changed in \"cida/config.py\"."
    else:
        DISPATCHER.Show()
    """
    DISPATCHER.Show()
    
if __name__ == "__main__":
    main()