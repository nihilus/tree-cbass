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
from dispatcher.core.structures.Tracer.CustomCallbacks import CustomApiFunctions as CustomApiFunctions
from dispatcher.core.structures.Tracer.Arch.x86.Linux import LinuxApiCallbacks as LinuxApiCallbacks
from dispatcher.core.structures.Tracer.AttachmodeCallbacks import AttachmodeFunctions as AttachmodeFunctions

windowsFileIO = None
linuxFileIO = None
customCallback = None
attachmodeCallback = None

#Need to have this first, evaluate everything with Python not IDC
idaapi.enable_extlang_python(True)

class TreeTracerPluginFormClass(PluginForm):
    
    def __init__(self):
        super(TreeTracerPluginFormClass, self).__init__()
        self.idaPluginDir = GetIdaDirectory() + "\\plugins\\"
        self.iconPath = self.idaPluginDir + "\\dispatcher\\icons\\"

        self.icon = QIcon(self.iconPath + "dispatcher.png")
        configReader = ConfigReader(self.idaPluginDir+"\\settings.ini")
        configReader.Read()
        self.version= configReader.version
        
    def setupWidgets(self):
        """
        Setup dispatcher widgets.
        """
        time_before = time.time()
        
        Print ("[/] setting up widgets...")
        global windowsFileIO,windowsNetworkIO,linuxFileIO,customCallback
        
        windowsFileIO = WindowsApiCallbacks.FileIO()
        windowsNetworkIO = WindowsApiCallbacks.NetworkIO()
        linuxFileIO = LinuxApiCallbacks.FileIO()
        customCallback = CustomApiFunctions()
        attachmodeCallback = AttachmodeFunctions()
        
        functionCallbacks = dict()
        functionCallbacks = {'windowsFileIO':windowsFileIO ,'linuxFileIO':linuxFileIO ,'customCallback':customCallback,'windowsNetworkIO':windowsNetworkIO,'attachmodeCallback':attachmodeCallback }
        
        layout = QtGui.QVBoxLayout()
        layout.addWidget(TraceGeneratorWidget(self,functionCallbacks))
        self.parent.setLayout(layout)

        Print("[\\] this took %3.2f seconds.\n" % (time.time() - time_before))
        
    def OnCreate(self, form):
        """
        When creating the form, setup the modules and widgets
        """
        self.printBanner()
        self.parent = self.FormToPySideWidget(form)
        self.parent.setWindowIcon(self.icon)
        self.setupWidgets()

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        Print("Plugin from closing.")

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
        print ("[+] Loading TREE Tracer version %s" % self.version)

    def Show(self):
        if idc.GetInputMD5() == None:
            return
        else:
            return PluginForm.Show(self,
                NAME,
                options=(PluginForm.FORM_CLOSE_LATER | PluginForm.FORM_RESTORE | PluginForm.FORM_SAVE))

class tracer_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = NAME
    help = "This is help"
    wanted_name = "TREE Tracer"
    wanted_hotkey = "Ctrl-F7"

    def init(self):
        Print("tracer_plugin_t installed")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = TreeTracerPluginFormClass()
        plg.Show()

    def term(self):
        Print("tracer_plugin_t uninstalled!")


def PLUGIN_ENTRY():
    return tracer_plugin_t()

