#############################################
 ___________________________________________ 
 \__    ___/\______   \_   _____/\_   _____/ 
    |    |    |       _/|    __)_  |    __)_ 
    |    |    |    |   \|        \ |        \ 
    |____|    |____|_  /_______  //_______  / 
                     \/        \/         \/  
#############################################
 Taint-enabled Reverse Engineering Environment
 by Battelle BIT Team                       
#############################################

++Requirements++
Python 2.7
PySide patched for IDA Pro
	- Windows (https://www.hex-rays.com/products/ida/support/ida/windows_pyside_python27_package.zip)
	- Linux (https://www.hex-rays.com/products/ida/support/ida/linux_pyside_python27_package.tgz)
	- Mac OSX (https://www.hex-rays.com/products/ida/support/ida/linux_pyside_python27_package.tgz)
Networkx 1.7
	-Numpy
	-scipy
	-matplotlib
IDA Pro 4.6x

++Components++
TREE_Analyzer.py
TREE_Tracer.py
--Core
	--Structures
		--Analyzer
		--Graph
		--Parse
		--Tracer
--Widgets
Analyzer - Main widget for taint generation upon a trace file/transfer from trace generator.
Concurrency
Visualizer - 