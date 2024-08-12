//
// Created by Xenia on 11.08.2024.
//

#ifndef REMEM_HPP
#define REMEM_HPP

#include <Windows.h>
#include <vector>
#include <iostream>
#include <regex>

#define _EXCEPTION_HANDLING 1

#define _LOGS 1

#if _EXCEPTION_HANDLING

#pragma code_seg(push, ".text")

__declspec(allocate(".text"))
#ifdef _X86_
UCHAR __checker[3] = { 0x8B, 0x01, 0xC3 };
#else
UCHAR __checker[4] = { 0x48, 0x8B, 0x01, 0xC3 };
#endif

#pragma code_seg()

#ifdef _X86_
#define BAD ((PVOID)0x1338caf0)
#else
#define BAD ((PVOID)0x1338cafebabef00d)
#endif

#ifdef _X86_
#define _PTR_MAX_VALUE ((PVOID)0xFFE00000)
#else
#define _PTR_MAX_VALUE ((PVOID)0x000F000000000000)
#endif

#endif

enum class CallingConvention
{
	cdecl_,
	stdcall_,
	thiscall_,
	fastcall_
};

namespace remem
{
#pragma region EXCEPTION_HANDLING
#if _EXCEPTION_HANDLING

	typedef PVOID(*tPointerChecker)(PVOID);

	static const tPointerChecker AvoidBadPtr = (tPointerChecker)&__checker;

	LONG WINAPI EH(EXCEPTION_POINTERS* ExceptionInfo)
	{
#ifdef _X86_
		if (ExceptionInfo->ContextRecord->Eip != (ULONG_PTR)__checker)
			return EXCEPTION_CONTINUE_SEARCH;
#else
		if (ExceptionInfo->ContextRecord->Rip != (ULONG_PTR)__checker)
			return EXCEPTION_CONTINUE_SEARCH;
#endif

#ifdef _X86_
		ExceptionInfo->ContextRecord->Eip += 2;
		ExceptionInfo->ContextRecord->Eax = (ULONG_PTR)BAD;
#else
		ExceptionInfo->ContextRecord->Rip += 3;
		ExceptionInfo->ContextRecord->Rax = (ULONG_PTR)BAD;
#endif

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	inline bool IsValidPtr(PVOID Ptr)
	{
		return (Ptr >= (PVOID)0x10000) && (Ptr < _PTR_MAX_VALUE) && AvoidBadPtr(Ptr) != BAD;
	}

#else

	bool IsValidPtr(void* ptr) {
		size_t size = sizeof(ptr);
		if (ptr == nullptr) {
			return false;
		}

		if (ptr <= (void*)0xFFFFFF || ptr >= (void*)0x7FFFFFFFFFFF) {
			return false;
		}

		MEMORY_BASIC_INFORMATION mbi;
		BYTE* p = (BYTE*)ptr;
		BYTE* maxp = p + size;
		while (p < maxp) {
			if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) {
				return false;
			}

			if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
				return false;
			}

			if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
				return false;
			}

			p += mbi.RegionSize;
		}

		return true;
	}

#endif

#if _EXCEPTION_HANDLING
	void SetupExceptionHandler()
	{
		AddVectoredExceptionHandler(1, EH);
	}
#endif
#pragma endregion
#pragma region MODULE_BASE
	template <typename T>
	T GetModuleBaseAddress()
	{
		return reinterpret_cast<T>(GetModuleHandleA(NULL));
	}

	template <typename T>
	T GetModuleBaseAddress(const char* _moduleName)
	{
		return reinterpret_cast<T>(GetModuleHandleA(_moduleName));
	}
#pragma endregion
#pragma region READ_MEMORY
	template <typename T>
	T ReadMemory(const auto& _address, const std::vector<DWORD>& _offsets)
	{
		auto _current = (uintptr_t)_address;
#if _LOGS
		std::cout << "Read Memory Address : " << std::hex << _current << std::endl;
#endif

		for (auto iter = _offsets.begin(); iter != _offsets.end(); ++iter)
		{
			DWORD _offset = *iter;

			if (!IsValidPtr(reinterpret_cast<void*>(_current)))
			{
#if _LOGS
				std::cerr << "Error: Null pointer dereferenced at Offset: " << std::hex << _offset << std::endl;
#endif
				return T{};
			}

			// for some reason it happened like this
			if (std::next(iter) == _offsets.end())
			{
				if constexpr (std::is_same_v<T, std::string>)
				{
					_current = (_current + _offset);
#if _LOGS
					std::cout << "Offset: " << std::hex << _offset << " | Offset Read Memory: " << std::hex << _current << std::endl;
#endif
					return std::string(reinterpret_cast<const char*>(_current));
				}
			}

			_current = *reinterpret_cast<uintptr_t*>(_current + _offset);
#if _LOGS
			std::cout << "Offset: " << std::hex << _offset << " | Offset Read Memory: " << std::hex << _current << std::endl;
#endif
		}

		if constexpr (std::is_pointer_v<T>)
		{
			if (!IsValidPtr(reinterpret_cast<void*>(_current)))
			{
#if _LOGS
				std::cerr << "Error: Invalid final memory address: " << std::hex << _current << std::endl;
#endif
				return T{};
			}
			return reinterpret_cast<T>(_current);
		}

		if constexpr (std::is_integral_v<T>)
		{
			return static_cast<T>(_current);
		}

		return T{};
	}
#pragma endregion
#pragma region WRITE_MEMORY
	template <typename T>
	void WriteMemory(const auto& _address, const std::vector<DWORD>& _offsets, T _value)
	{
		auto _current = (uintptr_t)_address;

		for (auto iter = _offsets.begin(); iter != _offsets.end(); ++iter)
		{
			DWORD _offset = *iter;
			if (!IsValidPtr(reinterpret_cast<void*>(_current)))
			{
#if _LOGS
				std::cerr << "Error: Null pointer dereferenced at Offset: " << std::hex << _offset << std::endl;
#endif
				return;
			}
			if (std::next(iter) == _offsets.end())
			{
				if (!IsValidPtr(reinterpret_cast<void*>(_current)))
				{
#if _LOGS
					std::cerr << "Error: Invalid final memory address: " << std::hex << _current << std::endl;
#endif
					return;
				}

				(*reinterpret_cast<T*>(_current + _offset)) = _value;
				return;
			}

			_current = *reinterpret_cast<uintptr_t*>(_current + _offset);
		}
	}
#pragma endregion
#pragma region FUNCTION_CALL
	template <CallingConvention Convention, typename ReturnType, typename... Args>
	struct FunctionType;

	template <typename ReturnType, typename... Args>
	struct FunctionType<CallingConvention::thiscall_, ReturnType, Args...>
	{
		using type = ReturnType(__thiscall*)(void*, Args...);
	};

	template <typename ReturnType, typename... Args>
	struct FunctionType<CallingConvention::fastcall_, ReturnType, Args...>
	{
		using type = ReturnType(__fastcall*)(void*, Args...);
	};

	template <typename ReturnType, typename... Args>
	struct FunctionType<CallingConvention::stdcall_, ReturnType, Args...>
	{
		using type = ReturnType(__stdcall*)(Args...);
	};

	template <typename ReturnType, typename... Args>
	struct FunctionType<CallingConvention::cdecl_, ReturnType, Args...>
	{
		using type = ReturnType(__cdecl*)(Args...);
	};

	template <CallingConvention Convention, typename ReturnType, typename... Args>
	auto CallFunction(const auto& _call_address, void* _this_pointer, Args... _args) -> std::enable_if_t<(Convention == CallingConvention::thiscall_ || Convention == CallingConvention::fastcall_), ReturnType>
	{
		using fn_t = typename FunctionType<Convention, ReturnType, Args...>::type;
		auto fn = reinterpret_cast<fn_t>(_call_address);
		return fn(_this_pointer, _args...);
	}

	template <CallingConvention Convention, typename ReturnType, typename... Args>
	auto CallFunction(const auto& _call_address, Args... _args) -> std::enable_if_t<(Convention != CallingConvention::thiscall_ && Convention != CallingConvention::fastcall_), ReturnType>
	{
		using fn_t = typename FunctionType<Convention, ReturnType, Args...>::type;
		auto fn = reinterpret_cast<fn_t>(_call_address);
		return fn(_args...);
	}

	template <int Index, typename ReturnType, typename... Args>
	auto VirtualCall(const void* _this_pointer, Args... _args)
	{
		using fn_t = ReturnType(__thiscall*)(void*, decltype(_args)...);
		auto fn = (*reinterpret_cast<fn_t**>(_this_pointer))[Index];
		return fn(_this_pointer, _args...);
	}
#pragma endregion
#pragma region PATTERN_SCAN
	std::uint8_t* find(std::string _pattern, const char* _module_name)
	{
		HMODULE module = (_module_name) ? GetModuleHandleA(_module_name) : GetModuleHandleA(NULL);

		if (!module)
			return nullptr;

		// Handle the conversion of a code style sig to an IDA one if required
		if (strstr(_pattern.c_str(), "\\x")) {
			// Fistly, convert \x to a space
			_pattern = std::regex_replace(_pattern, std::regex("\\\\x"), " ");

			// Remove any masks before converting 00's to a ?
			_pattern = std::regex_replace(_pattern, std::regex("x"), "");
			_pattern = std::regex_replace(_pattern, std::regex("\\?"), "");

			// Convert any 00's to ?
			_pattern = std::regex_replace(_pattern, std::regex("00"), "?");

			// Remove first space if there is one
			if (_pattern[0] == ' ')
				_pattern.erase(0, 1);
		}

		static const auto pattern_to_byte = [](const char* pattern)
			{
				auto bytes = std::vector<int>{};
				const auto start = const_cast<char*>(pattern);
				const auto end = const_cast<char*>(pattern) + std::strlen(pattern);

				for (auto current = start; current < end; ++current)
				{
					if (*current == '?')
					{
						++current;

						if (*current == '?')
							++current;

						bytes.push_back(-1);
					}
					else
					{
						bytes.push_back(std::strtoul(current, &current, 16));
					}
				}
				return bytes;
			};

		const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
		const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(module) + dos_header->e_lfanew);

		const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
		const auto pattern_bytes = pattern_to_byte(_pattern.c_str());
		const auto scan_bytes = reinterpret_cast<std::uint8_t*>(module);

		const auto pattern_size = pattern_bytes.size();
		const auto pattern_data = pattern_bytes.data();

		for (auto i = 0ul; i < size_of_image - pattern_size; ++i)
		{
			auto found = true;

			for (auto j = 0ul; j < pattern_size; ++j)
			{
				if (scan_bytes[i + j] == pattern_data[j] || pattern_data[j] == -1)
					continue;
				found = false;
				break;
			}
			if (!found)
				continue;
			return &scan_bytes[i];
		}

		return nullptr;
	}

	class pattern {
	public:
		pattern(std::string _pattern, const char* _module_name = nullptr)
		{
#ifdef _X86_
			this->_pointer = (uint32_t)find(_pattern, _module_name);
#else
			this->pointer = (uint64_t)find(_pattern, _module_name);
#endif
		}
		pattern add(uint32_t _value, bool _deref = false)
		{
			if (!_deref)
			{
				this->_pointer += _value;
				return *this;
			}
			else {
				this->_pointer += _value;
				this->_pointer = *reinterpret_cast<decltype(this->_pointer)*>(this->_pointer);
				return *this;
			}
		}
		pattern sub(uint32_t _value)
		{
			this->_pointer -= _value;
			return *this;
		}
		pattern inst(uint32_t _offset)
		{
			this->_pointer = *(int*)(this->_pointer + _offset) + this->_pointer;
			return *this;
		}

#ifdef _X86_
		pattern DerefPointer()
		{
		}
		uint32_t GetPointer()
		{
			return this->_pointer;
		}
#else
		uint64_t GetPointer()
		{
			return this->_pointer;
		}
#endif
	private:
#ifdef _X86_
		uint32_t _pointer;
#else
		uint64_t _pointer;
#endif
	};
#pragma endregion
};

#endif