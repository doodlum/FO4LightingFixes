#pragma once

#include "RE/N/NiLight.h"

namespace RE
{
	// BSLight is only forward-declared in CommonLibF4.  The three fields we need
	// live in the NiLight (or subclass) reachable through the pointer at +0xB8:
	//
	//   world position  — NiAVObject::world.translate  (+0xA0 in NiLight)
	//   app-culled flag — NiAVObject::GetAppCulled()   (+0x108 bit 0)
	//   effective radius — float at +0x138 in NiLight, which overlaps
	//       NiLight::spec.r in the current CommonLibF4 layout; the engine reads
	//       it as a radius, so it may belong to an unreversed NiPointLight
	//       subclass.  Exposed as lightRadius() until the full hierarchy is
	//       mapped.
	class BSLight : public NiRefObject
	{
	public:
		// members
		std::byte pad10[0xA8];  // 10
		NiLight*  light;        // B8

		[[nodiscard]] float lightRadius() const noexcept
		{
			if (!light) {
				return 0.0f;
			}
			return *reinterpret_cast<const float*>(
				reinterpret_cast<const std::uint8_t*>(light) + 0x138);
		}
	};
	static_assert(offsetof(BSLight, light) == 0xB8);
}
