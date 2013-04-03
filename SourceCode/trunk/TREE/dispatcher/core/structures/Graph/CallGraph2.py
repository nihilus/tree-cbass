from idaapi import *
from idautils import *
from idc import *
class CallGraph2(GraphViewer):
    def __init__(self, funcname, result):
        GraphViewer.__init__(self, "call graph of " + funcname)
        self.funcname = funcname
        self.result = result
    
    def OnRefresh(self):
        self.Clear()
        id = self.AddNode(self.funcname)
        for x in self.result.keys():
            callee = self.AddNode(x)
            self.AddEdge(id, callee)
        return True
        
    def OnGetText(self, node_id):
        return str(self[node_id])
    
    def OnCommand(self, cmd_id):
        '''
        Triggered when a menu command is selected through a menu or its hotkey
        @return: None
        '''
        if self.cmd_close == cmd_id:
            self.Close()
            return
        print "command:", cmd_id
    def Show(self):
        if not GraphViewer.Show(self):
            return False
        self.cmd_close = self.AddCommand("Close", "F2")
        if self.cmd_close == 0:
            print "Failed to add popup menu item!"
        return True