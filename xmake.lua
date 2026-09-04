set_xmakever("3.0.0")

set_languages("c++23")
set_warnings("allextra")
set_encodings("utf-8")

add_rules("mode.debug", "mode.releasedbg")

add_requires("safetyhook")

-- Before set_project: the subprojects call set_project themselves and the plugin
-- rule reads the global project name into the DLL's ProductName, so including
-- them afterwards lets the last one win.
includes("extern/CommonLibF4")

set_project("LightingFixes")
set_version("1.0.0")
set_license("GPL-3.0-or-later")

target("LightingFixes", function()
    set_version("1.0.0")
    set_license("GPL-3.0-or-later")

    -- Generates F4SEPlugin_Version and the DLL version resource.  No
    -- CompatibleVersions, address-library and struct-layout dependent for both
    -- runtime generations, so F4SE accepts it on any runtime it supports.
    add_rules("commonlibf4.plugin", {
        name = "LightingFixes",
        author = "doodlum",
        description = "Two fixes for per-object light lists: previs discarding them, and the wrong lights winning a pass's limited slots."
    })

    add_packages("safetyhook")

    add_files("src/**.cpp")
    add_includedirs("src")
    add_headerfiles("src/**.h")
    set_pcxxheader("src/PCH.h")
end)
