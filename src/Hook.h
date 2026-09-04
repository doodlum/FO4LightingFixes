#pragma once

#include <safetyhook.hpp>

#include <cstdint>
#include <string_view>

namespace Hook
{
	// CommonLibF4's runtime table stops at the flat game; asking REX::FModule about
	// Fallout 4 VR (1.2.72) terminates the process.  Everything here that depends
	// on the runtime goes through this instead, which answers VR from the file
	// version and defers to CommonLibF4 for the rest.
	enum class Runtime : std::uint8_t
	{
		kOG,  // 1.10.163
		kNG,  // 1.10.980/984
		kAE,  // 1.11.137-240
		kVR,  // 1.2.72
	};

	[[nodiscard]] Runtime GetRuntime();
	[[nodiscard]] bool    IsVR();

	// Expected opening bytes of an engine function, per runtime family.  IDA-style:
	// space-separated hex, "??" for a byte that cannot be pinned down (a
	// RIP-relative displacement, mostly).  Leave ng/ae/vr empty when the og pattern
	// serves that family too.
	//
	// This catches an address library entry resolving somewhere unintended on an
	// unmapped runtime.  It is not proof that a mapping is right: common prologue
	// bytes can match by accident.
	struct Pattern
	{
		std::string_view og;
		std::string_view ng;
		std::string_view ae;
		std::string_view vr;

		[[nodiscard]] std::string_view Get() const;
	};

	// One engine function across every runtime.  The flat game resolves through
	// the address library; VR has only ever shipped one executable, and its
	// address library is a csv that REL::IDDB cannot read, so VR is a fixed
	// image offset.  A zero VR offset means the function is unmapped there, and
	// Address() reports it rather than handing back the image base.
	struct Target
	{
		REL::VariantID flat;
		std::uintptr_t vr{ 0 };

		[[nodiscard]] std::uintptr_t Address() const;
	};

	// Checks the bytes without hooking, for addresses that are only ever called.
	// Those get no other verification.
	bool Verify(std::uintptr_t a_target, const Pattern& a_pattern, const char* a_what);

	bool Create(SafetyHookInline& a_out, std::uintptr_t a_target, void* a_hook,
		const Pattern& a_pattern, const char* a_what);
}
