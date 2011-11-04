About
=====

OllyCallTrace (Written in 2007) is a plugin for OllyDbg (version 1.10) to trace the call chain of a thread allowing you to monitor it for irregularities to aid in the debugging of stack based buffer overflows as well as to quickly plot the execution flow of a program you are reversing.

OllyCallTrace is based upon the script stack_integrity_monitor.py by Pedram Amini. 

Build
=====

To build OllyCallTrace from source, checkout the latest revision from the SVN trunk and then open OllyCallTraceGroup.bdsgroup with either Borland's Turbo C++ Explorer (free) or any recent version of C++ Builder and build the OllyCallTrace project. 

Usage
=====

Simply install the plugin and set a breakpoint on a location you want to trace from, e.g. ReadFile() or WSARecv(). When this breakpoint is hit, activate OllyCallTrace and press F7 to begin the automated single stepping and recording of the call chain. When you are finished tracing the code, pause execution or disable OllyCallTrace and view the OllyCallTrace Log to see the recorded call chain.

Double clicking on any Call/Return instruction in the OllyCallTrace Log window will bring you to that location in the OllyDbg disassembly window. The recorded call chain is highlighted with blue being for the main module, yellow for system modules and green for all other modules. The call chain is also displayed in a nested format to make it easier to read. All irregularities are marked in red.

Example
=======

This example shows how OllyCallTrace handles the recording of a stack based buffer overflow. In the screenshot below we can see where an overflow occurred when returning from the function at 0x00401198 and an attempt was made to return to 0x41414141. We can see that the return address should have been 0x0040120E which was originally called from 0x00401209. We can also note that the memset operation before the stack smash is suspicious and probably the cause of the vulnerability. This information would not have been available without OllyCallTrace recording the call chain as the stack is destroyed after the overflow. 

Screenshot
==========

![OllyCallTrace Screenshot 1](https://github.com/stephenfewer/OllyCallTrace/raw/master/screenshot1.gif "OllyCallTrace Screenshot 1")

License
=======

The OllyCallTrace source code is available under the GPLv3 license, please see the included file gpl-3.0.txt for details.
