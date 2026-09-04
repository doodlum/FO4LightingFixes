#pragma once

#include <safetyhook.hpp>

#include <cstdint>
#include <string_view>

namespace Hook
{
	// Expected opening bytes of an engine function, per runtime family.  IDA-style:
	// space-separated hex, "??" for a byte that cannot be pinned down (a
	// RIP-relative displacement, mostly).  Leave ng/ae empty when one pattern
	// serves every family.
	//
	// This catches an address library entry resolving somewhere unintended on an
	// unmapped runtime.  It is not proof that a mapping is right: common prologue
	// bytes can match by accident.
	struct Pattern
	{
		std::string_view og;
		std::string_view ng;
		std::string_view ae;

		[[nodiscard]] std::string_view Get() const;
	};

	// Checks the bytes without hooking, for addresses that are only ever called.
	// Those get no other verification.
	bool Verify(std::uintptr_t a_target, const Pattern& a_pattern, const char* a_what);

	bool Create(SafetyHookInline& a_out, std::uintptr_t a_target, void* a_hook,
		const Pattern& a_pattern, const char* a_what);
}
