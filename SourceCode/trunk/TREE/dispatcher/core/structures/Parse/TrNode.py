#
# Class for trace nodes
#
class Tr_Node(object):
  def __init__(self, initial = None):
    self.startind = initial
    
  def __str__(self):
    return self.ea
  
  def ExtractData(self, s):
    print s
    pattern = re.compile("(?P<type>\w) (?P<ea>[\d\w]+) [\d]+ [\w\d]+ (?P<ind1>[\d\w]+) (?P<ind2>[\d\w]+) Reg\((?P<instr>[\d\w\s=]+)\) (?P<anno>[\d\w\s_]+)?")
    m = pattern.search(s)
    self.typ = m.group('type')
    self.ea = m.group('ea')
    self.ind1 = m.group('ind1')
    self.ind2 = m.group('ind2')
    self.instr = m.group('instr')
    self.anno = m.group('anno')