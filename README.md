# PickyProfiler
Experimental selective x86/x64 function profiler. The profiler will measure functions
specified by a text file. Right now it only measures enters/exits and the average time
the function takes, this is open for improvement.

# How it works
The profiler will create a call at start of the function procedure and swaps the return
address to a routine that will take care of timing and control flow fixups. So whenever
a function enters it will notify the profiler of a function enter with a unique function id
and once the function returns the profiler will be called again to notify the exit and restores
the original return address. Each function gets its own entry/exit routine generated with AsmJIT 
to have a small footprint.

# NOTE
Currently only x86 is fully supported, x64 support is planned.

# Dependencies
Requires Zydis and AsmJIT, the best way to get them is to use vcpkg.

# Usage
Create a Functions.txt next to your target binary so that the folder structure
would look like following:
```
 Directory of C:\MyApp
 Functions.txt
 MyApp.exe
```

The Functions.txt format goes as following:
```
<rva32> [<function name>]
```
Example:
```
0x0027A462 myapp_function_1
0x0028820B myapp_function_2
0x0028840B
```
The last entry will be nameless and will show up as sub_(*).

Now all that is left to do is to start the process via the Loader
Example:
```
Loader.exe MyApp.exe
```
Which should result in a new text file called ProfilerReport.txt.
You can also inject the dll with other injectors or if you have the
source code available you can also just load the Picky.dll into your
process.