class ThreadNode(object):
    def __init__(self, initial = None):
        self.uuid=str(initial)

    def __str__(self):
        return self.e

    def label(self):
        return "[%s] %s_%s [%s]" % (self.e, self.t1, self.t2, self.desc)
        
    def parseMessage(self):
        message_split = self.message.split(',')
        self.e = message_split[0].strip().split('=')[1].strip()
        self.t1 = message_split[1].strip().split('=')[1].strip()
        self.desc = message_split[2].strip()
        if self.desc != "thread_precreate":
            self.t2 = message_split[3].strip().split('=')[1].strip()
        else:
            self.t2 = ""
    def extractData(self, s):
        #Temporary solution is to parse a text file until we get the C struct passed in
        import re
        pattern = re.compile("(?P<type>(event=|\[approve\]:)) \((?P<message>[\d\w\s,=]+)\)")
        m = pattern.search(s)
        self.typ = m.group('type')
        self.message = m.group('message')
        self.parseMessage()