#include "PCH.h"

#include "Settings.h"

#include <fstream>

namespace
{
	std::string ToLower(std::string_view a_value)
	{
		std::string out{ a_value };
		for (auto& c : out) {
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		}
		return out;
	}

	std::string Trim(std::string_view a_value)
	{
		constexpr std::string_view kSpace{ " \t\r\n" };
		const auto                 first = a_value.find_first_not_of(kSpace);
		if (first == std::string_view::npos) {
			return {};
		}
		const auto last = a_value.find_last_not_of(kSpace);
		return std::string{ a_value.substr(first, last - first + 1) };
	}

	// A trailing comment is not part of the value: without this,
	// `LightOrderFix = 1 ; note` parses as "1 ; note" and reads false.
	std::string_view StripComment(std::string_view a_value)
	{
		const auto cut = a_value.find_first_of(";#");
		return cut == std::string_view::npos ? a_value : a_value.substr(0, cut);
	}

	bool AsBool(std::string_view a_value)
	{
		const auto value = ToLower(a_value);
		return value == "1" || value == "true" || value == "yes" || value == "on";
	}

	// The ini ships beside this dll and is named after it.  Resolving from the
	// module path rather than the working directory matters: a plugin cannot assume
	// the process cwd is the game folder, and a launcher that sets it elsewhere
	// would silently leave every setting at its default.
	std::filesystem::path ModuleIniPath()
	{
		std::filesystem::path path{ REX::FModule::GetCurrentModule().GetFileName() };
		path.replace_extension(".ini");
		return path;
	}
}

Settings& Settings::Get() noexcept
{
	static Settings instance;
	return instance;
}

void Settings::Load()
{
	auto          path = ModuleIniPath();
	std::ifstream file{ path };
	if (!file) {
		// Fallback for a dll loaded from outside the plugins folder.
		path = "Data/F4SE/Plugins/LightingFixes.ini";
		file.open(path);
	}
	if (!file) {
		REX::INFO("no ini found; both fixes stay at their defaults");
		return;
	}

	std::string line;
	while (std::getline(file, line)) {
		const auto trimmed = Trim(line);
		if (trimmed.empty() || trimmed.front() == ';' || trimmed.front() == '#' ||
			trimmed.front() == '[') {
			continue;
		}
		const auto eq = trimmed.find('=');
		if (eq == std::string::npos) {
			continue;
		}
		const auto key = ToLower(Trim(std::string_view{ trimmed }.substr(0, eq)));
		const auto value =
			Trim(StripComment(std::string_view{ trimmed }.substr(eq + 1)));
		if (value.empty()) {
			continue;
		}
		if (key == "lightorderfix") {
			lightOrderFix = AsBool(value);
		} else if (key == "lightpriorityfix") {
			lightPriorityFix = AsBool(value);
		} else {
			REX::WARN("{}: unrecognised setting \"{}\"", path.filename().string(), key);
		}
	}
}
