#pragma once

struct Settings
{
	// Previs discards a node's light list after building it, so transparent objects
	// render with only the sun.  See LightOrderFix.h.
	bool lightOrderFix{ true };

	// An object lit by more lights than the pass can hold gets the four least
	// influential ones instead of the four most.  See LightPriorityFix.h.
	bool lightPriorityFix{ true };

	static Settings& Get() noexcept;

	// Reads LightingFixes.ini from beside the dll, falling back to
	// Data/F4SE/Plugins relative to the working directory.  Missing keys keep
	// their default.
	void Load();
};
