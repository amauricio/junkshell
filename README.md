# 🗑️ Junkshell: powershell shellcode loader
Sometimes, you need a fast way to encode your shellcode and execute it easily without being blocked by AV/EDR. Luminus is a PowerShell script designed to encode your shellcode and execute it directly in memory. The best part is the powershell script is different on each generation, so it's hard to detect.

## How it works

Junkshell utilizes an old technique based on `junk codes`. Essentially, it involves reserving a large chunk of memory and filling it with junk code. The shellcode is then placed at the end of this `junk code` and executed. This approach allows for bypassing AV/EDR detection, as the trick lies in using valid instructions instead of traditional `NOPs` to fill the memory. While `NOPs` are typically ignored by AV/EDR, using instructions like `xor eax, 0` or `sub eax, 0`, which do nothing but are still valid instructions, helps achieve successful execution of the shellcode.

![junk code shellcode](https://github.com/amauricio/junkshell/blob/master/resources/junk_code_shellcode.gif?raw=true)

## How to use it
```bash
python3 junkshell.py -s shellcode.bin -o revshell.ps1
```
It will generate a powershell script that you can run directly on the target machine.

## Actually works?

This is an example bypassing a meterpreter reverse shell in Sophos.

![junk code shellcode sophos](https://github.com/amauricio/junkshell/blob/master/resources/junk_code_shellcode_sophos.gif?raw=true)

## Output

```bash
[!]          Powershell script generated          [!]

You should run the powershell script below:

>> powershell.exe -exec Bypass -File data.ps1 <<
```

