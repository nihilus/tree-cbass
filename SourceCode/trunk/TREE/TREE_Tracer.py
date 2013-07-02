# TREE - Taint-enabled Reverse Engineering Environment 
# Copyright (c) 2013 Battelle BIT Team - Nathan Li, Xing Li, Loc Nguyen
#
# All rights reserved.
#
# For detailed copyright information see the file license.txt in the IDA PRO plugins folder
#---------------------------------------------------------------------
# TREE_Tracer.py - TREE Tracer plugin for IDA Pro
#---------------------------------------------------------------------

import os
import time

import idaapi
import idc

from idaapi import PluginForm
from PySide import QtGui
from PySide.QtGui import QIcon

from dispatcher.widgets.TraceGeneratorWidget import TraceGeneratorWidget

from dispatcher.core.DebugPrint import dbgPrint, Print

from dispatcher.core.Util import ConfigReader

NAME = "TREE Tracer"

from dispatcher.core.structures.Tracer.Arch.x86.Windows import WindowsApiCallbacks as WindowsApiCallbacks
from dispatcher.core.structures.Tracer.Arch.x86.Linux import LinuxApiCallbacks as LinuxApiCallbacks

windowsFileIO = None
linuxFileIO = None

#Need to have this first, evaluate everything with Python not IDC
idaapi.enable_extlang_python(True)

class TreeTracerPluginFormClass(PluginForm):
    """
    Tree Tracer plugin form
    """
    
    def __init__(self):
        super(TreeTracerPluginFormClass, self).__init__()
        self.idaPluginDir = os.path.join(GetIdaDirectory(),"plugins")
        print self.idaPluginDir
        self.iconPath = os.path.join(self.idaPluginDir, "dispatcher","icons")
        self.icon = QIcon( self.iconPath )
        ini_path = os.path.join(self.idaPluginDir,"settings.ini")
        print ini_path
        configReader = ConfigReader()
        configReader.Read(ini_path)

        self.version= configReader.version
        
    def setupWidgets(self):
        """
        Setup dispatcher widgets.
        """
        time_before = time.time()
        
        Print ("[/] setting up widgets...")
        global windowsFileIO,windowsNetworkIO,linuxFileIO
        
        windowsFileIO = WindowsApiCallbacks.FileIO()
        windowsNetworkIO = WindowsApiCallbacks.NetworkIO()
        linuxFileIO = LinuxApiCallbacks.FileIO()

        functionCallbacks = dict()
        functionCallbacks = {'windowsFileIO':windowsFileIO ,'linuxFileIO':linuxFileIO ,'windowsNetworkIO':windowsNetworkIO }
        
        layout = QtGui.QVBoxLayout()
        layout.addWidget(TraceGeneratorWidget(self,functionCallbacks))
        self.parent.setLayout(layout)

        Print("[\\] this took %3.2f seconds.\n" % (time.time() - time_before))
        
    def OnCreate(self, form):
        """
        When creating the form, setup the modules and widgets
        """
        print("OnCreate Called.")
        self.printBanner()
        self.parent = self.FormToPySideWidget(form)
        self.parent.setWindowIcon(self.icon)
        self.setupWidgets()

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        print("Plugin form closing.")

    def printBanner(self):
        """
        Prints the banner for the TREE Tracer plugin
        """
        
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
        print ("[+] Loading TREE Tracer version %s" % self.version)

    def Show(self):
        """
        Called when the plugin form is visible
        """
        
        if idc.GetInputMD5() == None:
            return
        else:
            return PluginForm.Show(self,
                NAME,
                options=(PluginForm.FORM_CLOSE_LATER | PluginForm.FORM_RESTORE | PluginForm.FORM_SAVE))

class tracer_plugin_t(idaapi.plugin_t):
    """
    TREE Tracer plugin
    """
    flags = idaapi.PLUGIN_UNL
    help = ""
    comment = "TREE Tracer plugin for IDA"
    wanted_name = "TREE Tracer"
    wanted_hotkey = "Ctrl-F7"

    def init(self):
        Print("tracer_plugin_t installed")
        ExTraces = None
        ExTraces = idaapi.netnode("$ ExTraces", 0, False) #Get the execution trace id
        data = ExTraces.getblob(0, 'A')
        if data is None:
            print "This IDB has no TREE Trace. Turn ON TREE Tracer"
            return idaapi.PLUGIN_OK
        else:
            print "This IDB has TREE Trace. Turn OFF TREE Trace"
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        """
        Called when the plugin runs
        """
        
        Print("tracer_plugin_t run!")
        plg = TreeTracerPluginFormClass()
        plg.Show()
        
        return

    def term(self):
        """
        Called when the plugsin terminates
        """
        
        Print("tracer_plugin_t uninstalled!")

def PLUGIN_ENTRY():
    return tracer_plugin_t()

