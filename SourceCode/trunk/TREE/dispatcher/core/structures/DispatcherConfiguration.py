import os

class DispatcherConfiguration():
    """
    Contain config information
    """
    def __init__(self, configuration, os_ref=None):
        import os
        self.os_sep = os.sep
        try:
            self.os_path_normpath = self.os.path.normpath
        except:
            self.os_path_normpath = None
        #default config
        self.dispatcher_plugin_only = False
        self.root_file_path = ""
        self.icon_file_path = ""
        ##load trace generator
        ##load taint analyzer
        self._loadConfig(configuration)
        
    def _loadConfig(self, configuration):
        self.root_file_path = configuration["paths"]["dispatcher_root_dir"]
        self.dispatcher_plugin_only = configuration["plugin_only"]
        self.icon_file_path = self.root_file_path + self.os_sep \
            + "dispatcher" + self.os_sep + "icons" + self.os_sep
        self.config_path_sep = configuration["config_path_sep"]
        ##load trace generator
        ##load taint analyzer
        
    def _normalizePath(self, path):
        if self.os_path_normpath is None:
            return path
        else:
            parts = path.split(self.config_path_sep)
            return self.os_path_normpath(self.os.sep.join(parts))
    
    def __str__(self):
        return "Dispatcher configuration: \n" \
            + " root_file_path: %s\n" % self.root_file_path \
            + " icon_file_path: %s\n" % self.icon_file_path \