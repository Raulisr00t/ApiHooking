# Function Hooking Examples
## Overview
This project demonstrates function hooking using a trampoline technique. The hook intercepts calls to the MessageBoxA function, replacing it with a custom implementation (MyMessageBoxA). This example is designed to work with both 32-bit and 64-bit applications.

## Table of Contents
Features
Requirements
Usage
Code Structure
How It Works
Troubleshooting
License

### Features
Hooks the MessageBoxA function to replace its behavior.
Demonstrates how to install and remove hooks.
Works with both 32-bit and 64-bit applications.
Provides debugging output to trace hook installation and removal.

### Requirements
Windows OS (both 32-bit and 64-bit versions supported)
A C compiler that supports the Windows.h header and basic C library functions.

### Usage
Compile the Code

To compile the code, use a C compiler that supports Windows API functions. For example, you can use Microsoft Visual Studio:
```powershell
cl /EHsc hook_example.c
```
Run the Executable

Execute the compiled program. It will first show the original MessageBoxA behavior, then hook the function to replace it with a custom message box, and finally restore the original function.
```cmd
ApiHooking.exe
```
## Code Structure
HookSt Structure: Defines the hook state, including pointers to the function to be hooked, the replacement function, original bytes, and old protection.
InitializeHookStruct: Initializes the hook structure and saves the original function bytes.
InstallHook: Replaces the target function's bytes with a trampoline that redirects execution to the hook function.
RemoveHook: Restores the original function bytes and reverts memory protection.
MyMessageBoxA: Custom function that replaces MessageBoxA. It prints original parameters and displays a custom message.
main: Demonstrates hooking and unhooking of MessageBoxA.

### How It Works
Initialization:

InitializeHookStruct is called to prepare the hook structure. It saves the original bytes of the target function (MessageBoxA) and sets up memory protection.
Installation:

InstallHook replaces the start of the target function with a trampoline. This trampoline is an assembly snippet that jumps to the custom function (MyMessageBoxA).
Execution:

When MessageBoxA is called, it triggers MyMessageBoxA, showing a custom message box and logging the original parameters.
Removal:

RemoveHook restores the original function bytes and resets memory protection.

### Troubleshooting
VirtualProtect Failure: Ensure you have appropriate permissions to modify the target function's memory. Running the application with elevated privileges may help.
Hooking Issues: Ensure the TRAMPOLINE_SIZE is correctly defined for the target architecture (32-bit or 64-bit).

## License
This project is licensed under the MIT License. See the LICENSE file for details.
