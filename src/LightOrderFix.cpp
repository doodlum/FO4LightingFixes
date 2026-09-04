#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#ifdef ERROR
#	undef ERROR
#endif

#include "PCH.h"

#include "LightOrderFix.h"

#include "Hook.h"

#include <memory>
#include <new>

namespace
{
	// VariantID slots are (OG = 1.10.163, NG = 1.10.980/984, AE = 1.11.137-240).
	// NG and AE share one id space, so the AE id serves both.  None of these ids
	// exist in the 1.10.163 database, which is a different id space; each function
	// was located in that binary separately.
	//
	// VR (1.2.72) is a fixed image offset, read out of the VR binary.  The PDB
	// names it carries are given for each; the VR address library, whose ids are
	// the 1.10.163 ones where a function matches, agrees on every entry it has
	// (`remove` 981017, driver 222957, pre-culling query 917969) and lacks the
	// other two.
	//                                 1.10.163  1.10.980/984  1.11.137-240    1.2.72
	const Hook::Target kRemove{ REL::VariantID{ 981017u, 2319061u, 2319061u }, 0x28F1FB0 };           // BSShaderPropertyLightData::RemoveLight
	const Hook::Target kTeardownDriver{ REL::VariantID{ 222957u, 2317472u, 2317472u }, 0x27EB2C0 };   // ShadowSceneNode::UpdateQueuedLight
	const Hook::Target kApply{ REL::VariantID{ 1210164u, 2318420u, 2318420u }, 0x286E470 };           // BSLight::AddFadeNodeLocked
	const Hook::Target kPreCullingActive{ REL::VariantID{ 917969u, 2317322u, 2317322u }, 0x27E0D50 };  // BSPreCulledObjects::QEnabled

	// `remove` and the teardown driver were recompiled between 1.10.163 and
	// 1.11.240, so their expected bytes are per-runtime as well as their ids.  OG
	// and NG get five bytes rather than sixteen: neither binary is on hand, and a
	// longer pattern would refuse on any recompile.  VR's `remove` keeps only the
	// fence test and the stamp; the array search is split into a helper it calls.
	const Hook::Pattern kRemovePattern{
		.og = "48 89 54 24 10",
		.ng = "48 89 5C 24 10",
		.ae = "48 89 5C 24 10 56 48 83 EC 30 BE FF FF FF FF 4C",
		.vr = "48 89 54 24 10 53 48 83 EC 20 83 39 FF 48 8B D9",
	};
	const Hook::Pattern kTeardownPattern{
		.og = "48 89 74 24 20",
		.ng = "48 89 54 24 10",
		.ae = "48 89 54 24 10 56 57 41 54 41 57 48 83 EC 38 44",
		.vr = "48 89 74 24 20 57 41 54 41 57 48 83 EC 30 44 8B",
	};

	// Located in 1.10.163 by masked signature against the 1.11.240 bytes, so their
	// prologues agree across all three families, and VR's are byte-identical.  The
	// pre-culling query opens with two `cmp byte ptr [rip+disp32], 0`; the
	// displacements are wildcarded.
	const Hook::Pattern kApplyPattern{
		.og = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48",
	};
	const Hook::Pattern kPreCullingPattern{
		.og = "80 3D ?? ?? ?? ?? 00 74 15 80 3D ?? ?? ?? ?? 00",
	};

	// node -> list.  VR's NiAVObject carries 0x40 more bytes ahead of the
	// BSFadeNode members, so its list sits further in; the list itself (fence,
	// stamp, BSTArray) is laid out the same.
	constexpr std::ptrdiff_t kLightDataFlat = 0x140;
	constexpr std::ptrdiff_t kLightDataVR = 0x180;
	constexpr std::ptrdiff_t kArray = 0x10;     // list -> BSLight**
	constexpr std::ptrdiff_t kCount = 0x20;     // list -> count
	constexpr std::ptrdiff_t kRefCount = 0x08;  // NiRefObject::refCount

	std::ptrdiff_t g_lightData = kLightDataFlat;  // set in Install

	constexpr std::size_t kMaxLights = 32;
	constexpr std::size_t kMaxPending = 512;

	struct Pending
	{
		const void*                   list{ nullptr };
		void*                         node{ nullptr };
		std::array<void*, kMaxLights> lights{};
		std::uint32_t                 count{ 0 };
		std::uint32_t                 removed{ 0 };  // bitmask over lights
	};

	struct PendingSet
	{
		std::array<Pending, kMaxPending> items{};
		std::size_t                      count{ 0 };
	};

	// Queued and drained inside one teardown frame on one thread, so nothing is
	// shared and no lock is needed.  Allocated on demand: only the thread running
	// the teardown driver pays the ~140 KB.
	thread_local std::unique_ptr<PendingSet> t_pending;
	thread_local std::uint32_t               t_depth = 0;

	std::atomic<bool> g_warnedFull{ false };

	bool (*g_preCullingActive)() = nullptr;
	void (*g_apply)(void*, void*) = nullptr;

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

	// A light is unlinked from the node before it is put back, so nothing else
	// holds it in that window.  NiRefObject-derived: refCount at +0x08, DeleteThis
	// at vtable slot 1, matching the engine's own `inc lock [rdi+8]` / `xadd lock`
	// + `call [rax+8]`.
	void Retain(void* a_object) noexcept
	{
		auto* count = reinterpret_cast<volatile LONG*>(
			static_cast<std::uint8_t*>(a_object) + kRefCount);
		InterlockedIncrement(count);
	}

	void Release(void* a_object) noexcept
	{
		auto* count = reinterpret_cast<volatile LONG*>(
			static_cast<std::uint8_t*>(a_object) + kRefCount);
		if (InterlockedDecrement(count) != 0) {
			return;
		}
		std::uintptr_t vtable{};
		if (!Read(a_object, &vtable) || !vtable) {
			return;
		}
		std::uintptr_t deleteThis{};
		if (!Read(reinterpret_cast<const void*>(vtable + 0x08), &deleteThis) ||
			!deleteThis) {
			return;
		}
		reinterpret_cast<void (*)(void*)>(deleteThis)(a_object);
	}

	Pending* Find(const void* a_list) noexcept
	{
		auto& pending = *t_pending;
		for (std::size_t i = 0; i < pending.count; ++i) {
			if (pending.items[i].list == a_list) {
				return &pending.items[i];
			}
		}
		return nullptr;
	}

	// Snapshots the list as it is before the teardown starts emptying it, which is
	// the list the rebuild just produced.
	Pending* Open(const void* a_list) noexcept
	{
		auto& pending = *t_pending;
		if (pending.count >= kMaxPending) {
			if (!g_warnedFull.exchange(true)) {
				REX::WARN("light order fix: one light was attached to more than {} "
						  "nodes; the rest keep vanilla behaviour",
					kMaxPending);
			}
			return nullptr;
		}

		auto* node = static_cast<std::uint8_t*>(const_cast<void*>(a_list)) - g_lightData;

		std::uint32_t count{};
		void**        array{};
		if (!Read(static_cast<const std::uint8_t*>(a_list) + kCount, &count) ||
			!Read(static_cast<const std::uint8_t*>(a_list) + kArray, &array) || !array ||
			count == 0) {
			return nullptr;
		}

		// The put-back writes to the node after the driver returns, so the node has
		// to survive until then.  Both remove call sites follow with
		// `cmp dword ptr [node+0x8], 1` and a notification, so nodes can die inside
		// the walk.  Skipping one already at its last reference leaves that test
		// unchanged: it compares against 1, and only nodes at 2 or more are held.
		std::uint32_t refs{};
		if (!Read(node + kRefCount, &refs) || refs <= 1) {
			return nullptr;
		}

		auto& p = pending.items[pending.count];
		p = {};
		p.list = a_list;
		p.node = node;

		const auto take = count < kMaxLights ? count : static_cast<std::uint32_t>(kMaxLights);
		for (std::uint32_t i = 0; i < take; ++i) {
			if (!Read(array + i, &p.lights[i])) {
				return nullptr;
			}
		}
		p.count = take;

		Retain(node);
		++pending.count;
		return &p;
	}

	// The gather copies the first entries, and the engine's add appends once the
	// list is closed, so an appended put-back would send a different subset to the
	// shader.  This is a permutation of the same pointers and the same count.
	void RestoreOrder(const void* a_list, const Pending& a_pending) noexcept
	{
		std::uint32_t count{};
		void**        array{};
		if (!Read(static_cast<const std::uint8_t*>(a_list) + kCount, &count) ||
			!Read(static_cast<const std::uint8_t*>(a_list) + kArray, &array) || !array ||
			count == 0 || count > kMaxLights) {
			return;
		}

		std::array<void*, kMaxLights> ordered{};
		std::size_t                   n = 0;

		const auto present = [&](void* a_light) {
			for (std::uint32_t j = 0; j < count; ++j) {
				void* have{};
				if (Read(array + j, &have) && have == a_light) {
					return true;
				}
			}
			return false;
		};
		const auto taken = [&](void* a_light) {
			for (std::size_t k = 0; k < n; ++k) {
				if (ordered[k] == a_light) {
					return true;
				}
			}
			return false;
		};

		for (std::uint32_t i = 0; i < a_pending.count && n < kMaxLights; ++i) {
			if (a_pending.lights[i] && present(a_pending.lights[i])) {
				ordered[n++] = a_pending.lights[i];
			}
		}
		for (std::uint32_t j = 0; j < count && n < kMaxLights; ++j) {
			void* have{};
			if (!Read(array + j, &have) || !have) {
				continue;
			}
			if (!taken(have)) {
				ordered[n++] = have;
			}
		}
		if (n != count) {
			return;  // not a total permutation; leave it alone
		}
		__try {
			for (std::size_t i = 0; i < n; ++i) {
				array[i] = ordered[i];
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	// Leaked on purpose: F4SE plugins are never unloaded, and letting these
	// destruct at process exit would unhook while a render thread may still be
	// inside the trampoline.
	SafetyHookInline& g_remove = *new SafetyHookInline{};

	std::uintptr_t Remove(void* a_list, void* a_light)
	{
		// Only removals made by the teardown driver are ours to undo: `remove` is
		// also reached from the app-culled path, which jumps past the teardown call,
		// and queuing there would put a culled light back.  And only previs inverts
		// the order -- with it off the teardown runs first, so a removal there is
		// discarding last frame's list.
		if (t_depth != 0 && t_pending && a_list && a_light && g_preCullingActive()) {
			auto* p = Find(a_list);
			if (!p) {
				p = Open(a_list);
			}
			if (p) {
				for (std::uint32_t i = 0; i < p->count; ++i) {
					if (p->lights[i] == a_light) {
						if ((p->removed & (1u << i)) == 0) {
							p->removed |= 1u << i;
							Retain(a_light);
						}
						break;
					}
				}
			}
		}
		return g_remove.call<std::uintptr_t>(a_list, a_light);
	}

	SafetyHookInline& g_teardown = *new SafetyHookInline{};

	// REL::ID(2317472) tears down one light's node associations.  Applying from
	// inside it would append to the very list it is walking, so the put-back waits
	// until it has returned.
	std::uintptr_t Teardown(void* a_root, void* a_light)
	{
		if (!t_pending) {
			t_pending.reset(new (std::nothrow) PendingSet{});
			if (!t_pending) {
				return g_teardown.call<std::uintptr_t>(a_root, a_light);
			}
		}

		++t_depth;
		const auto result = g_teardown.call<std::uintptr_t>(a_root, a_light);
		--t_depth;

		if (t_depth != 0) {
			return result;  // an outer frame owns the drain
		}

		// Nothing can add entries here: queuing needs a teardown frame on this
		// thread, and the engine's apply never reaches `remove`.
		auto& pending = *t_pending;
		for (std::size_t i = 0; i < pending.count; ++i) {
			const auto& p = pending.items[i];
			for (std::uint32_t j = 0; j < p.count; ++j) {
				if ((p.removed & (1u << j)) == 0 || !p.lights[j]) {
					continue;
				}
				g_apply(p.lights[j], p.node);
				Release(p.lights[j]);
			}
			if (p.removed != 0) {
				RestoreOrder(p.list, p);
			}
			Release(p.node);  // taken in Open, unconditionally
		}
		pending.count = 0;
		return result;
	}
}

namespace LightOrderFix
{
	bool Install()
	{
		g_lightData = Hook::IsVR() ? kLightDataVR : kLightDataFlat;

		// Verified before anything is patched.  These two are only ever called, so
		// the byte check is all that stands between a stale mapping and a call into
		// an arbitrary function with (light, node).
		const auto applyAddress = kApply.Address();
		const auto preCullingAddress = kPreCullingActive.Address();
		const bool applyOk = Hook::Verify(applyAddress, kApplyPattern,
			"light order fix (apply)");
		const bool preCullingOk = Hook::Verify(preCullingAddress, kPreCullingPattern,
			"light order fix (pre-culling query)");
		if (!applyOk || !preCullingOk) {
			return false;  // the hooks would call these; do not install them
		}
		g_apply = reinterpret_cast<void (*)(void*, void*)>(applyAddress);
		g_preCullingActive = reinterpret_cast<bool (*)()>(preCullingAddress);

		// Deliberately not short-circuited: on an unmapped runtime every failure is
		// worth seeing at once, not just the first.
		const bool remove = Hook::Create(g_remove, kRemove.Address(),
			reinterpret_cast<void*>(&Remove), kRemovePattern,
			"light order fix (remove)");
		const bool teardown = Hook::Create(g_teardown, kTeardownDriver.Address(),
			reinterpret_cast<void*>(&Teardown), kTeardownPattern,
			"light order fix (teardown)");
		if (!remove || !teardown) {
			// Half the pair is worse than neither: the remove hook only queues under
			// a teardown frame, so alone it is dead weight in a hot path.  Safe to
			// drop at load time; nothing is rendering yet, which is why these are
			// leaked at shutdown instead.
			g_remove = {};
			g_teardown = {};
			return false;
		}
		return true;
	}
}
