# remem - Memory Manipulation Library

`remem` is a C++20 header-only library designed for safely reading and writing memory in Windows applications. It includes features like exception handling, pointer validation, and memory manipulation utilities, making it a useful tool for low-level memory operations.

## Features

- **Memory Reading and Writing**: Easily read and write memory at specified addresses with support for multiple offsets.
- **Pointer Validation**: Ensure that pointers are valid before accessing memory, preventing crashes or undefined behavior.
- **Pattern Scanning**: Find byte patterns in memory with support for both IDA-style signatures and code style signatures.
- **Function Calling**: Call functions with different calling conventions, including support for member functions (with `this` pointer).
- **Exception Handling**: (Optional) Safeguard against exceptions during pointer dereferencing by using a vectored exception handler.
- **Logging**: (Optional) Log memory addresses and offsets during read/write operations for debugging purposes.

## Installation

To use `remem` in your project, simply include the `remem.hpp` header file in your code. No additional dependencies are required.

## Usage

### 1. Setup Exception Handler (Optional)

If you want to enable exception handling, you should set up the exception handler at the beginning of your program:

```cpp
remem::SetupExceptionHandler();
```

### 2. Reading Memory

You can read memory using the ReadMemory function template. It supports reading from an address with multiple offsets:

```cpp
uintptr_t baseAddress = remem::GetModuleBaseAddress<uintptr_t>("module_name.exe");
std::vector<DWORD> offsets = {0x10, 0x20, 0x30};
int value = remem::ReadMemory<int>(baseAddress, offsets);
```

If you want to read a string from memory:

```cpp
std::string value = remem::ReadMemory<std::string>(baseAddress, offsets);
```

### 3. Writing Memory

Similarly, you can write to memory using the WriteMemory function template:

```cpp
int newValue = 12345;
remem::WriteMemory<int>(baseAddress, offsets, newValue);
```

### 4. Writing Memory

Before performing any operations on a pointer, you can validate it:

```cpp
void* ptr = reinterpret_cast<void*>(address);
if (remem::IsValidPtr(ptr)) {
    // Safe to use the pointer
}
```

### 5. Function calling

The CallFunction template allows you to call functions with different calling conventions in C++. Here’s how to use it:

#### 1. Determine the Calling Convention

Decide which calling convention your function uses (`thiscall`, `fastcall`, `stdcall`, or `cdecl`).

#### 2. Define the Function Signature

Specify the return type and parameters of the function you want to call.

#### 3. Call the Function

**For thiscall and fastcall conventions, you need to pass a this pointer as the first argument.**

**For stdcall and cdecl conventions, you do not need to pass a this pointer.**

#### Example Usage

**To call a thiscall or fastcall function, provide the address of the function, a this pointer, and the arguments:**

```cpp
auto result = CallFunction<CallingConvention::thiscall_, ReturnType>(funcAddress, thisPointer, arg1, arg2);
```

**To call a stdcall or cdecl function, provide the address of the function and the arguments:**

```cpp
auto result = CallFunction<CallingConvention::cdecl_, ReturnType>(funcAddress, arg1, arg2);
```

In both cases, replace `ReturnType` with the return type of the function and `funcAddress` with the address of the function you are calling.

### 6. Pattern Scanning

The pattern class allows for easy memory pattern scanning with support for both IDA-style signatures and code-style signatures.

`pattern` Class

**Constructor**

**```pattern(std::string _pattern, const char* _module_name = nullptr)```**: Constructs a pattern object by scanning for the specified pattern in the given module (or the current module if nullptr).

**Member Functions**

**```pattern add(uint32_t _value, bool _deref = false)```**: Adds an offset to the current pointer. If _deref is true, it will also dereference the pointer before adding the offset.

**```pattern sub(uint32_t _value)```**: Subtracts an offset from the current pointer.

**```pattern inst(uint32_t _offset)```**: Adds an offset to the current pointer, with the offset value taken from a pointer located at _offset from the current pointer.

**```GetPointer()```**: Returns the current pointer value.

#### Example Usage

For example we are pattern scanning ```mov ecx, [0xDEADBEEF]```

```cpp
auto PatternTest = remem::pattern("8B 0D ?? ?? ?? ??").add(2, true);
```

The add member will deref the pointer if we call ```auto insideofmovecx = PatternTest.GetPointer()``` it will return 0xDEADBEEF.

## Configuration


### Exception Handling

Exception handling can be enabled or disabled by setting the _EXCEPTION_HANDLING macro:

```cpp
#define _EXCEPTION_HANDLING 1  // Enable exception handling
```

### Logging

Logging can be enabled or disabled by setting the _LOGS macro:

```cpp
#define _LOGS 1 
```

## Platform Support

This library is designed specifically for Windows and utilizes Windows-specific APIs.

## License

This library is provided as-is, with no warranties or guarantees. Use it at your own risk.

## Author

Created by 0xenia on 11.08.2024.
