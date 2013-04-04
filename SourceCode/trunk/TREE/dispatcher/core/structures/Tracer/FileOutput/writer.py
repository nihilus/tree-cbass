# writer.py

__version__ = "$Revision: 16dd63848921 $"
# $Source$

#---------------------------------------------------------------------
# Writer to capture output
#
# 
# Author: Nathan Li, Xing Li
#
#---------------------------------------------------------------------

import cStringIO

MAX_BUFFER_SIZE = 5

class BufferWriter():
    """
    Buffer Writer class for writing data to a memory buffer first then flushing it to a file
    This should be faster then direct IO because we are writing to memory
    
    Call fileOpen to create an output file
    Call writeToFile to write data to a memory buffer
    Call fileClose to flush the memory buffer to a file and close the file
    
    """
    
    def __init__(self):
        self.output = cStringIO.StringIO()
    
    def fileOpen(self,filename):
        self.file=file(filename,'wb')
        
    def writeToFile(self,data):
        self.output.write(data)
        
        """
        content = self.output.getvalue()
        contentSize =  len(content)
        
        if contentSize > MAX_BUFFER_SIZE:
            print "Writing called"
            self.file.write(content)
            self.output.close()
            self.output = cStringIO.StringIO()
        """
        
    def fileClose(self):
        contents = self.output.getvalue() #Get all the data content
        self.file.write(contents) #Write the data content to a file
        
        self.output.close() #Close the memory buffer

        self.file.close() #Close the actual file
        
class FileWriter():
    """
    File Writer writes data to a file
    
    Call fileOpen to create an output file
    Call writeToFile to write to the file
    Call fileClose to close the file
    
    """
    
    def __init__(self):
        self.file=None
        self.filename = None
    
    def fileOpen(self,filename):
        self.file=file(filename,'wb')
        self.filename = filename
        
    def writeToFile(self,data):
            
        self.file.write(data)
    
    def fileClose(self):
        self.file.close()
    
if __name__ == '__main__':
    fileEx = FileWriter()
    fileEx.fileOpen(".\\FileTest.txt")
    fileEx.writeToFile("Hello")
    fileEx.fileClose()
    
    memEx = BufferWriter()
    memEx.fileOpen(".\\BufferTest.txt")
    memEx.writeToFile("Hello34132412343214231432432423412423412341234")
    memEx.fileClose()