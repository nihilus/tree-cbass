import os
import time

import idaapi
import idc

from idaapi import PluginForm
from PySide import QtGui
from PySide.QtGui import QIcon

import dispatcher.config as config
from dispatcher.core.structures.DispatcherConfiguration import DispatcherConfiguration
from dispatcher.widgets.TraceGeneratorWidget import TraceGeneratorWidget

NAME = "TREE Tracer v0.1"

from dispatcher.core.structures.Tracer.Arch.x86.Windows import WindowsApiCallbacks as WindowsApiCallbacks
from dispatcher.core.structures.Tracer.CustomCallbacks import CustomApiFunctions as CustomApiFunctions
from dispatcher.core.structures.Tracer.Arch.x86.Linux import LinuxApiCallbacks as LinuxApiCallbacks

windowsFileIO = None
linuxFileIO = None
customCallback = None

#Need to have this first, evaluate everything with Python not IDC
idaapi.enable_extlang_python(True)

class TreeTracerPluginFormClass(PluginForm):
    
    def __init__(self):
        super(TreeTracerPluginFormClass, self).__init__()
        print "TreeTracerPluginFormClass init called."
        
        self.dispatcher_widgets = []
        self.ensureRootPathSanity(config.configuration)
        self.config = DispatcherConfiguration(config.configuration)
        self.icon = QIcon(self.config.icon_file_path + "dispatcher.png")
    
    def ensureRootPathSanity(self, configuration):
        
        try:
            root_dir = configuration["paths"]["dispatcher_root_dir"]
            print root_dir
            if not os.path.exists(root_dir) or not "TREE_Tracer.py" in os.listdir(root_dir):
                resolved_pathname = os.path.dirname(sys.argv[0])
                if "TREE_Tracer.py" in os.listdir(resolved_pathname):
                    print "[+] Tree Tracer root directory successfully resolved"
                    configuration["paths"]["dispatcher_root_dir"] = resolved_pathname
                else:
                    print "[-] TREE_Tracer.py is not resolvable"
                    raise Exception()
        except:
            print "[!] Dispatcher config is broken. Could not locate root directory. " \
                 + "Try setting the field \"dispatcher_root_dir\" to the path where \"TREE_Tracer.py\" is located."
            sys.exit(-1)
            
    def setupTreeTracerPluginForm(self):
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
        
    def setupWidgets(self):
        """
        Setup dispatcher widgets.
        """
        time_before = time.time()
        print ("[/] setting up widgets...")
        global windowsFileIO,linuxFileIO,customCallback
        
        windowsFileIO = WindowsApiCallbacks.FileIO()
        linuxFileIO = LinuxApiCallbacks.FileIO()
        customCallback = CustomApiFunctions()
        
        functionCallbacks = dict()
        functionCallbacks = {'windowsFileIO':windowsFileIO ,'linuxFileIO':linuxFileIO ,'customCallback':customCallback }
        
        self.dispatcher_widgets.append(TraceGeneratorWidget(self,functionCallbacks))

        self.setupTreeTracerPluginForm()
        print("[\\] this took %3.2f seconds.\n" % (time.time() - time_before))
        
    def OnCreate(self, form):
        """
        When creating the form, setup the modules and widgets
        """
        self.printBanner()
        #print "TreeTracerPluginFormClass OnCreate called."
        self.parent = self.FormToPySideWidget(form)
        self.parent.setWindowIcon(self.icon)
        self.setupWidgets()

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        #idaapi.msg("Plugin from closing.")

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
        print ("[+] Loading TREE Tracer...")

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
        print("tracer_plugin_t installed")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        plg = TreeTracerPluginFormClass()
        plg.Show()

    def term(self):
        print("tracer_plugin_t uninstalled!")


def PLUGIN_ENTRY():
    return tracer_plugin_t()

