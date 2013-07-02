# TREE - Taint-enabled Reverse Engineering Environment 
# Copyright (c) 2013 Battelle BIT Team - Nathan Li, Xing Li, Loc Nguyen
#
# All rights reserved.
#
# For detailed copyright information see the file license.txt in the IDA PRO plugins folder
#---------------------------------------------------------------------
# writer.py - writes data either to a file or to memory
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
        """
        opens a file for writing
        @param filename: The name of the file
        @return: None
        """
        self.file=file(filename,'wb')
        
    def writeToFile(self,data):
        """
        writes data to a memory buffer
        @param data: The data to write
        @return: None
        """
        
        self.output.write(data)
    
    def getBufferData(self):
        """
        returns the buffer stored in memory
        @param: None
        @return: buffer in memory
        """
        return self.output.getvalue()
    
    def fileClose(self,data):
        """
        files an opened file, flushes the data
        This function is mainly used for testing.  We wanted to confirm the content of the buffer is the same as the content of the file
        @param data: the data to write
        @return: None
        """ 
        self.file.write(data) #Write the data content to a file

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
    
    def fileOpen(self,filename):
        """
        opens a file for writing
        @param filename: The name of the file
        @return: None
        """
        self.file=file(filename,'wb')
        
    def writeToFile(self,data):
        """
        writes the data to an opened file
        @param data: The data to write
        @return: None
        """
        self.file.write(data)
    
    def fileClose(self):
        """
        close a file the was opened
        @param: None
        @return: None
        """
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