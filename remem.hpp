//
// Created by Xenia on 11.08.2024.
//

#ifndef REMEM_HPP
#define REMEM_HPP

#include <Windows.h>
#include <vector>
#include <iostream>

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

namespace remem
{
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

	template <typename T>
	T ReadMemory(const auto& _address, const std::vector<DWORD>& _offsets)
	{
		auto _current = (uintptr_t)(_address);
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
			if (std::next(iter) == _offsets.end() && std::is_same_v<T, std::string>)
			{
				_current = (_current + _offset);
#if _LOGS
				std::cout << "Offset: " << std::hex << _offset << " | Offset Read Memory: " << std::hex << _current << std::endl;
#endif
				return std::string(reinterpret_cast<const char*>(_current));
			}

			_current = *reinterpret_cast<uintptr_t*>(_current + _offset);
#if _LOGS
			std::cout << "Offset: " << std::hex << _offset << " | Offset Read Memory: " << std::hex << _current << std::endl;
#endif
		}

		if (!IsValidPtr(reinterpret_cast<void*>(_current)))
		{
#if _LOGS
			std::cerr << "Error: Invalid final memory address: " << std::hex << _current << std::endl;
#endif
			return T{};
		}

		if constexpr (std::is_integral_v<T>)
		{
			return static_cast<T>(_current);
		}

		return T{};
	}

	template <typename T>
	void WriteMemory(const auto& _address, const std::vector<DWORD>& _offsets, T _value)
	{
		auto _current = (uintptr_t)(_address);

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
};

#endif