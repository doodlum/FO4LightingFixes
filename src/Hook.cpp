#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#ifdef ERROR
#	undef ERROR
#endif

#include "PCH.h"

#include "Hook.h"

namespace
{
	constexpr std::size_t kMaxPattern = 32;

	struct Parsed
	{
		std::array<std::uint8_t, kMaxPattern> bytes{};
		std::array<bool, kMaxPattern>         wild{};
		std::size_t                           size{ 0 };
	};

	constexpr int HexDigit(char a_c) noexcept
	{
		if (a_c >= '0' && a_c <= '9') {
			return a_c - '0';
		}
		if (a_c >= 'a' && a_c <= 'f') {
			return a_c - 'a' + 10;
		}
		if (a_c >= 'A' && a_c <= 'F') {
			return a_c - 'A' + 10;
		}
		return -1;
	}

	constexpr Parsed Parse(std::string_view a_pattern) noexcept
	{
		Parsed      out{};
		std::size_t i = 0;
		while (i < a_pattern.size()) {
			if (a_pattern[i] == ' ') {
				++i;
				continue;
			}
			if (out.size >= kMaxPattern) {
				return {};
			}
			if (a_pattern[i] == '?') {
				out.wild[out.size++] = true;
				++i;
				if (i < a_pattern.size() && a_pattern[i] == '?') {
					++i;
				}
				continue;
			}
			const auto hi = HexDigit(a_pattern[i]);
			const auto lo = i + 1 < a_pattern.size() ? HexDigit(a_pattern[i + 1]) : -1;
			if (hi < 0 || lo < 0) {
				return {};
			}
			out.bytes[out.size++] = static_cast<std::uint8_t>((hi << 4) | lo);
			i += 2;
		}
		return out;
	}

	// An id that resolved outside the mapped image may not be readable at all.
	bool ReadBytes(const void* a_addr, std::uint8_t* a_out, std::size_t a_size) noexcept
	{
		__try {
			std::memcpy(a_out, a_addr, a_size);
			return true;
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	std::string Format(const std::uint8_t* a_bytes, const bool* a_wild, std::size_t a_size)
	{
		std::string out;
		out.reserve(a_size * 3);
		for (std::size_t i = 0; i < a_size; ++i) {
			if (i != 0) {
				out += ' ';
			}
			if (a_wild && a_wild[i]) {
				out += "??";
			} else {
				out += std::format("{:02x}", a_bytes[i]);
			}
		}
		return out;
	}
}

namespace Hook
{
	// An empty ng/ae falls back to og, so one pattern can serve every family.
	std::string_view Pattern::Get() const
	{
		switch (REX::FModule::GetRuntimeIndex()) {
		case REX::FModule::Runtime::kNG:
			return ng.empty() ? og : ng;
		case REX::FModule::Runtime::kAE:
			return ae.empty() ? og : ae;
		default:
			return og;
		}
	}

	bool Verify(std::uintptr_t a_target, const Pattern& a_pattern, const char* a_what)
	{
		const auto pattern = a_pattern.Get();
		const auto parsed = Parse(pattern);
		if (parsed.size == 0) {
			REX::ERROR("{}: no byte pattern for this runtime; refusing to touch {:#x}",
				a_what, a_target);
			return false;
		}

		std::array<std::uint8_t, kMaxPattern> got{};
		if (!ReadBytes(reinterpret_cast<const void*>(a_target), got.data(), parsed.size)) {
			REX::ERROR("{}: {:#x} is not readable; not hooking", a_what, a_target);
			return false;
		}

		for (std::size_t i = 0; i < parsed.size; ++i) {
			if (!parsed.wild[i] && got[i] != parsed.bytes[i]) {
				REX::ERROR("{}: unexpected bytes at {:#x}\n  got    {}\n  wanted {}",
					a_what, a_target,
					Format(got.data(), nullptr, parsed.size),
					Format(parsed.bytes.data(), parsed.wild.data(), parsed.size));
				return false;
			}
		}
		return true;
	}

	bool Create(SafetyHookInline& a_out, std::uintptr_t a_target, void* a_hook,
		const Pattern& a_pattern, const char* a_what)
	{
		if (!Verify(a_target, a_pattern, a_what)) {
			return false;
		}

		a_out = safetyhook::create_inline(reinterpret_cast<void*>(a_target), a_hook);
		if (!a_out) {
			REX::ERROR("{}: could not hook {:#x}", a_what, a_target);
			return false;
		}
		return true;
	}
}
