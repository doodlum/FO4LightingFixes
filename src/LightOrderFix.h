#pragma once

// Previs discards a node's light list after building it.
//
// A BSFadeNode's light list is at node+0x140: fence +0x00, stamp +0x08, BSTArray
// at +0x10 (data, capacity, size at +0x20).  Each frame the list is rebuilt --
// open (fence = 0), add per light (fence += 1), close (detach past the fence,
// fence = -1) -- and every light is separately torn out of every node list it is
// in.  With previs off that teardown runs first; with previs on the rebuild is
// deferred to a flush REL::ID(2318569) that runs before the teardown driver
// REL::ID(2317472), so the teardown discards the list that was just built.  An
// empty list still yields the sun, hence dark blue glass.
//
// Fix: snapshot the node's light array when the teardown first touches it, and
// once the driver has returned, re-apply the removed lights in snapshot order.
// The gather takes only the first few entries and the engine's add push-backs on a
// closed list, so restoring the order matters as much as the membership.
//
// Constraints, both read out of the engine:
//   - REL::ID(2319061) is also reached from the app-culled path, which jumps past
//     the teardown call.  Queuing is gated on being inside a teardown frame, or a
//     culled light gets put back by an unrelated light's drain.
//   - Both remove call sites follow with `cmp dword ptr [node+0x8], 1` and a
//     notification, so nodes can die mid-walk.  Lights and node are referenced for
//     the window; a node already at its last reference is skipped instead, which
//     leaves that comparison unchanged.
//
// Removals are queued and drained on the same thread, so the pending set is
// thread-local and unlocked.
namespace LightOrderFix
{
	bool Install();
}
