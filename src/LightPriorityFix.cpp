#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#ifdef ERROR
#	undef ERROR
#endif

#include "PCH.h"

#include "LightPriorityFix.h"

#include "Hook.h"
#include "RE/BSLight.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace
{
	// NG and AE share one address-library id space; only 1.10.163 needs its own.
	// VR (1.2.72) is a fixed image offset: BSShaderPropertyLightData::
	// CreateActiveLightList in the VR binary, which its address library lacks.
	//                              1.10.163  1.10.980/984  1.11.137-240    1.2.72
	const Hook::Target kGather{ REL::VariantID{ 1312870u, 2319067u, 2319067u }, 0x28F2150 };

	// The 1.10.163 gather is instruction-for-instruction identical to 1.11.240's,
	// and VR's differs only in the two sun displacements past these bytes, so one
	// pattern covers every family.
	const Hook::Pattern kGatherPattern{
		.og = "48 89 5C 24 08 80 7C 24 28 00 45 8B D8 48 8B DA",
	};

	// What moved in VR.  NiAVObject is 0x40 larger, which pushes the node's
	// list along; NiLight carries the radius 0x40 further in; and the two sun
	// slots the gather copies from its context sit 0x40 later as well.  The
	// world position, bounds and flags sit inside the part of NiAVObject that
	// did not grow.
	struct Layout
	{
		std::ptrdiff_t lightData;    // node -> list
		std::ptrdiff_t innerRadius;  // NiLight -> radius
		std::ptrdiff_t sun;          // ctx -> sun, a_alt == false
		std::ptrdiff_t sunAlt;       // ctx -> sun, a_alt == true
	};

	constexpr Layout kLayoutFlat{ 0x140, 0x138, 0x1F8, 0x208 };
	constexpr Layout kLayoutVR{ 0x180, 0x178, 0x238, 0x248 };

	Layout g_layout = kLayoutFlat;  // set in Install

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
		RE::BSLight*  light;
		float         weight;
		std::uint32_t index;
	};

	// REL::ID(2318430), recomputed: the weight the engine stored lives in the
	// attach's temporary buffer, which is freed before the gather runs.
	bool Weigh(RE::BSLight* a_light, const RE::NiBound& a_bounds, float* a_out) noexcept
	{
		auto* niLight = a_light->light;
		if (!niLight) {
			return false;
		}
		float radius{};
		if (!Read(reinterpret_cast<const std::uint8_t*>(niLight) + g_layout.innerRadius, &radius)) {
			return false;
		}
		const auto& pos = niLight->world.translate;
		const auto  dx = pos.x - a_bounds.center.x;
		const auto  dy = pos.y - a_bounds.center.y;
		const auto  dz = pos.z - a_bounds.center.z;
		const auto  distance = std::sqrt(dx * dx + dy * dy + dz * dz);
		// The engine divides by this unguarded; rank a degenerate light last
		// instead of producing a NaN that would poison the comparison.
		const auto weight = radius > 0.0f ? (distance - a_bounds.fRadius) / radius : kRankLast;
		if (std::isnan(weight)) {
			return false;
		}
		*a_out = std::clamp(weight, -kRankLast, kRankLast);
		return true;
	}

	bool Culled(RE::BSLight* a_light) noexcept
	{
		auto* niLight = a_light->light;
		if (!niLight) {
			return false;
		}
		return niLight->GetAppCulled();
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

		auto* list = static_cast<RE::BSShaderPropertyLightData*>(a_list);
		const auto count = list->lightList.size();
		if (count == 0) {
			return original();
		}

		const auto slots = a_max - 1;  // slot 0 belongs to the sun
		if (count <= slots || count > kMaxRank) {
			return original();
		}

		// The gather's list argument is a node's embedded list; every engine site
		// derives it that way.  Requiring finite bounds rejects a NaN node
		// transform, which would make every weight NaN, and catches a list that
		// was not a node's.
		auto* node = reinterpret_cast<RE::BSFadeNode*>(
			reinterpret_cast<std::uint8_t*>(list) - g_layout.lightData);

		const auto& bounds = node->worldBound;
		if (!std::isfinite(bounds.center.x) || !std::isfinite(bounds.center.y) ||
			!std::isfinite(bounds.center.z) || !std::isfinite(bounds.fRadius)) {
			return original();
		}

		std::array<Ranked, kMaxRank> ranked{};
		std::size_t                  n = 0;
		for (std::uint32_t i = 0; i < count; ++i) {
			auto* light = list->lightList[i];
			// The original stores nulls and lets them consume a slot; rather than
			// reproduce that, hand the whole call back.
			if (!light) {
				return original();
			}
			if (Culled(light)) {
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
		if (!Read(static_cast<const std::uint8_t*>(a_ctx) +
					  (a_alt ? g_layout.sunAlt : g_layout.sun),
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
		g_layout = Hook::IsVR() ? kLayoutVR : kLayoutFlat;
		return Hook::Create(g_gather, kGather.Address(),
			reinterpret_cast<void*>(&Gather), kGatherPattern, "light priority fix");
	}
}
