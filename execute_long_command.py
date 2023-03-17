import ctypes, struct
import sys
import winpwn
argument=sys.argv[1]


#double hash instruction are for attaching debugger
import os
import subprocess
def main():

    space="\\x"
    #if you want \x or space as hex separator
    sh,output=winpwn.winexec_one_command(argument,space)
    print("Shellcode: "  + output )
    print("Bytes: " + str(len(sh)))
    print("Attaching debugger to " + str(os.getpid()));
    subprocess.Popen(["WinDbgX", "/g","/p", str(os.getpid())], shell=True)
    winpwn.run_shellcode_w4so(sh)

 
if __name__ == "__main__":
    main()