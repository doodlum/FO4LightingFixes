#pragma once

// An object lit by more lights than the pass can hold gets the wrong ones.
//
// The pass holds five: the sun plus four.  On rebuild each candidate is weighed by
// REL::ID(2318430):
//
//     weight = (|lightPos - boundsCenter| - bounds.radius) / light.radius
//
// a normalised distance, so smaller means more strongly lit.  The (light, weight)
// pairs are sorted and attached in sorted order, so the sort order becomes the
// list order.  But the comparator returns -1 when a.weight > b.weight -- it sorts
// descending -- and the gather REL::ID(2319067) scans forward taking the first
// four.  The four slots go to the four least influential lights.
//
// At a chemistry station with the flashlight on, seven lights competing: the
// flashlight (-0.017) misses by one slot while a light 467 units away (+0.509)
// gets in, and the light closest to the glass is dropped even with the flashlight
// off.  Backing away appears to fix it because retreating raises the flashlight's
// weight and promotes it up the descending list.
//
// Fix: keep the engine's metric and the gather's contract, and select the most
// influential entries instead, emitted in list order so the output has the same
// shape -- sun in slot 0, the rest in list order.  Lists that already fit, and
// anything unexpected, fall back to the original.  The list itself is untouched,
// which confines the change to this one call.
//
// Affects every object lit by more than four lights, not just glass.
namespace LightPriorityFix
{
	bool Install();
}
