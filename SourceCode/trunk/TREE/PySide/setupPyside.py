import shutil
import os
import sys

def copytree(src, dst, symlinks=False, ignore=None):
    if not os.path.exists(dst):
        os.makedirs(dst)
    
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, symlinks, ignore)
        else:
            shutil.copy2(s, d)

if __name__ == '__main__':

    #src = "C:\\Users\\xing\\Documents\\TREE\\PySide\\"
    #dst = "C:\\Python27\\Lib\\site-packages\\PySide\\"
    src = sys.argv[1]
    dst = sys.argv[2]
    copytree(src, dst)
