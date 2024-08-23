# R0m4NTAPI

## Disclaimer
R0m4NTAPI is intended for educational purposes only. This tool is designed to help users understand process injection techniques and NTAPI functions within a controlled, legal environment.

Do not use this tool for any malicious or unauthorized activities. The author is not responsible for any misuse of this tool. Always obtain proper authorization before using this tool on any system.

## Overview

**R0m4NTAPI** is a shellcode injection tool that demonstrates how to inject arbitrary shellcode into a target process using native NTAPI functions. This project is designed for educational purposes, helping users understand low-level process manipulation techniques on Windows platforms.

## Features

- **Process Injection**: Injects shellcode into a target process using NTAPI functions.
- **Memory Management**: Allocates and protects memory within the target process.
- **Thread Execution**: Creates a remote thread in the target process to execute the injected shellcode.
- **Error Handling**: Includes robust error handling and logging for easier debugging and stability.

## Getting Started

### Prerequisites

- **Operating System**: Windows 10 or later.
- **Development Environment**: Visual Studio or any C/C++ compiler supporting Windows APIs.
- **Permissions**: Administrator privileges may be required for injecting into certain processes.

### Building the Project

1. Clone the repository:
    ```bash
    git clone https://github.com/AbdouRoumi/R0m4NTAPI.git
    cd R0m4NTAPI
    ```

2. Open the project in Visual Studio or compile it using your preferred C/C++ compiler.

3. Build the project:
    - In Visual Studio, select `Build > Build Solution`.
    - Alternatively, use `cl` from the command line:
      ```bash
      cl /EHsc /Fe:R0m4NTAPI.exe R0m4NTAPI.cpp
      ```

### Usage

1. Run the injector with the target process ID:
    ```bash
    R0m4NTAPI.exe <PID>
    ```

2. The injector will:
   - Open a handle to the target process.
   - Allocate memory in the target process.
   - Write the shellcode to the allocated memory.
   - Change memory protection to executable.
   - Create a remote thread in the target process to execute the shellcode.

### Example

```bash
R0m4NTAPI.exe 1234
