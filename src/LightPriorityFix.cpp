#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#ifdef ERROR
#	undef ERROR
#endif

#include "PCH.h"

#include "LightPriorityFix.h"

#include "Hook.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace
{
	// NG and AE share one address-library id space; only 1.10.163 needs its own.
	//                              1.10.163  1.10.980/984  1.11.137-240
	const REL::VariantID kGather{ 1312870u, 2319067u, 2319067u };

	// The 1.10.163 gather is instruction-for-instruction identical to 1.11.240's,
	// so one pattern covers every family.
	const Hook::Pattern kGatherPattern{
		.og = "48 89 5C 24 08 80 7C 24 28 00 45 8B D8 48 8B DA",
	};

	constexpr std::ptrdiff_t kLightData = 0x140;    // node -> list
	constexpr std::ptrdiff_t kArray = 0x10;         // list -> BSLight**
	constexpr std::ptrdiff_t kCount = 0x20;         // list -> count
	constexpr std::ptrdiff_t kBounds = 0xB0;        // node -> cx, cy, cz, radius
	constexpr std::ptrdiff_t kInner = 0xB8;         // light -> data block
	constexpr std::ptrdiff_t kInnerPos = 0xA0;      // data -> world position
	constexpr std::ptrdiff_t kInnerRadius = 0x138;  // data -> radius
	constexpr std::ptrdiff_t kInnerFlags = 0x108;   // data -> bit 0 = app-culled

	// Only has to be big enough to rank one node's list.
	constexpr std::size_t kMaxRank = 64;

	// Ranks last without being an infinity: a non-finite weight makes the
	// comparator below a non-ordering, and std::partial_sort on one that is not a
	// strict weak ordering is undefined and can walk off the array.
	constexpr float kRankLast = std::numeric_limits<float>::max();

	template <class T>
	bool Read(const void* a_addr, T* a_out) noexcept
	{
		__try {
			std::memcpy(a_out, a_addr, sizeof(T));
			return true;
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	struct Ranked
	{
		void*         light;
		float         weight;
		std::uint32_t index;
	};

	// REL::ID(2318430), recomputed: the weight the engine stored lives in the
	// attach's temporary buffer, which is freed before the gather runs.
	bool Weigh(void* a_light, const float* a_bounds, float* a_out) noexcept
	{
		const void* inner{};
		if (!Read(static_cast<const std::uint8_t*>(a_light) + kInner, &inner) || !inner) {
			return false;
		}
		const auto* ib = static_cast<const std::uint8_t*>(inner);
		float       pos[3]{};
		float       radius{};
		if (!Read(ib + kInnerPos, &pos) || !Read(ib + kInnerRadius, &radius)) {
			return false;
		}
		const auto dx = pos[0] - a_bounds[0];
		const auto dy = pos[1] - a_bounds[1];
		const auto dz = pos[2] - a_bounds[2];
		const auto distance = std::sqrt(dx * dx + dy * dy + dz * dz);
		// The engine divides by this unguarded; rank a degenerate light last
		// instead of producing a NaN that would poison the comparison.
		const auto weight = radius > 0.0f ? (distance - a_bounds[3]) / radius : kRankLast;
		if (std::isnan(weight)) {
			return false;
		}
		*a_out = std::clamp(weight, -kRankLast, kRankLast);
		return true;
	}

	bool Culled(void* a_light, bool* a_out) noexcept
	{
		const void* inner{};
		if (!Read(static_cast<const std::uint8_t*>(a_light) + kInner, &inner) || !inner) {
			return false;
		}
		std::uint8_t flags{};
		if (!Read(static_cast<const std::uint8_t*>(inner) + kInnerFlags, &flags)) {
			return false;
		}
		*a_out = (flags & 0x1) != 0;
		return true;
	}

	// Leaked on purpose: see LightOrderFix.cpp.
	SafetyHookInline& g_gather = *new SafetyHookInline{};

	std::uint32_t Gather(void* a_list, void** a_out, std::uint32_t a_max, void* a_ctx,
		bool a_alt)
	{
		// Anything unexpected hands the whole call back to the engine.
		const auto original = [&] {
			return g_gather.call<std::uint32_t>(a_list, a_out, a_max, a_ctx, a_alt);
		};

		if (!a_list || !a_out || !a_ctx || a_max < 2) {
			return original();
		}

		std::uint32_t count{};
		void**        array{};
		const auto*   lb = static_cast<const std::uint8_t*>(a_list);
		if (!Read(lb + kCount, &count) || !Read(lb + kArray, &array) || !array) {
			return original();
		}

		const auto slots = a_max - 1;  // slot 0 belongs to the sun
		if (count <= slots || count > kMaxRank) {
			return original();
		}

		// The gather's list argument is node + 0x140; every engine site derives it
		// that way.  Requiring finite bounds rejects a NaN node transform, which
		// would make every weight NaN, and catches a list that was not a node's.
		float bounds[4]{};
		if (!Read(lb - kLightData + kBounds, &bounds)) {
			return original();
		}
		if (!std::ranges::all_of(bounds, [](float f) { return std::isfinite(f); })) {
			return original();
		}

		std::array<Ranked, kMaxRank> ranked{};
		std::size_t                  n = 0;
		for (std::uint32_t i = 0; i < count; ++i) {
			void* light{};
			// The original stores nulls and lets them consume a slot; rather than
			// reproduce that, hand the whole call back.
			if (!Read(array + i, &light) || !light) {
				return original();
			}
			bool culled{};
			if (!Culled(light, &culled)) {
				return original();
			}
			if (culled) {
				continue;  // skipped without spending a slot, as the original does
			}
			float weight{};
			if (!Weigh(light, bounds, &weight)) {
				return original();
			}
			ranked[n++] = Ranked{ light, weight, i };
		}
		if (n <= slots) {
			return original();
		}

		std::partial_sort(ranked.begin(), ranked.begin() + slots, ranked.begin() + n,
			[](const Ranked& a, const Ranked& b) { return a.weight < b.weight; });
		std::sort(ranked.begin(), ranked.begin() + slots,
			[](const Ranked& a, const Ranked& b) { return a.index < b.index; });

		const void* sun{};
		if (!Read(static_cast<const std::uint8_t*>(a_ctx) + (a_alt ? 0x208 : 0x1F8),
				&sun)) {
			return original();
		}

		__try {
			a_out[0] = const_cast<void*>(sun);
			for (std::uint32_t i = 0; i < slots; ++i) {
				a_out[i + 1] = ranked[i].light;
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			return original();
		}
		return a_max;
	}
}

namespace LightPriorityFix
{
	bool Install()
	{
		return Hook::Create(g_gather, kGather.address(),
			reinterpret_cast<void*>(&Gather), kGatherPattern, "light priority fix");
	}
}
