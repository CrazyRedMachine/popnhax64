// clang-format off
#include <windows.h>
#include <psapi.h>
// clang-format on

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "util/fuzzy_search.h"

#include "minhook/hde32.h"
#include "minhook/include/MinHook.h"

#include "popnhax/config.h"
#include "util/patch.h"
#include "util/xmlprop.hpp"

#define PROGRAM_VERSION "0.1.dev"

FILE *g_log_fp = NULL;

#define LOG(...) do { \
if (g_log_fp != NULL) { \
fprintf(g_log_fp, __VA_ARGS__); \
fflush(g_log_fp);\
 }\
fprintf(stderr, __VA_ARGS__); \
} while (0)

struct popnhax_config config = {};

PSMAP_BEGIN(config_psmap, static)
PSMAP_MEMBER_REQ(PSMAP_PROPERTY_TYPE_BOOL, struct popnhax_config, unset_volume,
                 "/popnhax/unset_volume")
PSMAP_MEMBER_REQ(PSMAP_PROPERTY_TYPE_BOOL, struct popnhax_config, event_mode, "/popnhax/event_mode")
PSMAP_MEMBER_REQ(PSMAP_PROPERTY_TYPE_BOOL, struct popnhax_config, remove_timer,
                 "/popnhax/remove_timer")
PSMAP_MEMBER_REQ(PSMAP_PROPERTY_TYPE_BOOL, struct popnhax_config, freeze_timer,
                 "/popnhax/freeze_timer")
PSMAP_MEMBER_REQ(PSMAP_PROPERTY_TYPE_BOOL, struct popnhax_config, unlock_all, "/popnhax/unlock_all")
PSMAP_MEMBER_REQ(PSMAP_PROPERTY_TYPE_BOOL, struct popnhax_config, skip_tutorials,
                 "/popnhax/skip_tutorials")
PSMAP_END

double g_multiplier = 1.;
DWORD (*real_timeGetTime)();
DWORD patch_timeGetTime()
{
 static DWORD last_real = 0;
 static DWORD cumul_offset = 0;

 if (last_real == 0)
 {
     last_real = real_timeGetTime()*g_multiplier;
     return last_real;
 }

 DWORD real = real_timeGetTime()*g_multiplier;
 DWORD elapsed = real-last_real;
 if (elapsed > 16) cumul_offset+= elapsed;

 last_real = real;
 return real - cumul_offset;

}

bool patch_get_time(double time_rate)
{
    if (time_rate == 0)
        return true;

    g_multiplier = time_rate;
    HMODULE hinstLib = GetModuleHandleA("winmm.dll");
    MH_CreateHook((LPVOID)GetProcAddress(hinstLib, "timeGetTime"), (LPVOID)patch_timeGetTime,
                      (void **)&real_timeGetTime);

    LOG("popnhax: time multiplier: %f\n", time_rate);
    return true;
}

static bool patch_unset_volume() {
    DWORD dllSize = 0;
    char *data = getDllData("popn22.dll", &dllSize);

    int64_t first_loc = 0;

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x04\x00\x81\xC4\x00\x01\x00\x00\xC3\xCC", 10)

        first_loc = find_block(data, dllSize, &task, 0);
        if (first_loc == -1) {
            return false;
        }
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x83", 1)

        int64_t pattern_offset = find_block(data, 0x10, &task, first_loc);
        if (pattern_offset == -1) {
            return false;
        }

        uint64_t patch_addr = (int64_t)data + pattern_offset;
        patch_memory(patch_addr, (char *)"\xC3", 1);
    }

    printf("popnhax: windows volume untouched\n");

    return true;
}

static bool patch_event_mode() {
    DWORD dllSize = 0;
    char *data = getDllData("popn22.dll", &dllSize);

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0,
                   "\x8B\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
                   "\xCC\xCC\xC7",
                   17)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
            return false;
        }

        uint64_t patch_addr = (int64_t)data + pattern_offset;
        patch_memory(patch_addr, (char *)"\x31\xC0\x40\xC3", 4);
    }

    printf("popnhax: event mode forced\n");

    return true;
}

static bool patch_remove_timer() {
    DWORD dllSize = 0;
    char *data = getDllData("popn22.dll", &dllSize);

    int64_t first_loc = 0;

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x8B\xAC\x24\x68\x01", 5)

        first_loc = find_block(data, dllSize, &task, 0);
        if (first_loc == -1) {
            return false;
        }
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x0F", 1)

        int64_t pattern_offset = find_block(data, 0x15, &task, first_loc);
        if (pattern_offset == -1) {
            return false;
        }

        uint64_t patch_addr = (int64_t)data + pattern_offset;
        patch_memory(patch_addr, (char *)"\x90\xE9", 2);
    }

    printf("popnhax: timer removed\n");

    return true;
}

static bool patch_freeze_timer() {
    DWORD dllSize = 0;
    char *data = getDllData("popn22.dll", &dllSize);

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\xC7\x45\x38\x09\x00\x00\x00", 7)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
            return false;
        }

        uint64_t patch_addr = (int64_t)data + pattern_offset;
        patch_memory(patch_addr, (char *)"\x90\x90\x90\x90\x90\x90\x90", 7);
    }

    printf("popnhax: timer frozen at 10 seconds remaining\n");

    return true;
}

static bool patch_hidden_charts_3() {
    DWORD dllSize = 0;
    char *data = getDllData("popn22.dll", &dllSize);

    bool patched = false;
    while (1) {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x80\x00\x00\x03", 4)

        int64_t pattern_offset = find_block(data, 0x50000, &task, 0x2A0000);
        if (pattern_offset == -1) {
            break;
        }

        uint64_t patch_addr = (int64_t)data + pattern_offset;

        //        printf("popnhax: found hidden chart (03) at %llx\n", patch_addr);
        patch_memory(patch_addr, (char *)"\x00\x00\x00\x03", 4);
        patched = true;
    }

    if (patched) {
        printf("popnhax: found and unlocked hidden charts (03)\n");
    }

    return patched;
}

static bool patch_hidden_charts_7() {
    DWORD dllSize = 0;
    char *data = getDllData("popn22.dll", &dllSize);

    bool patched = false;
    while (1) {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x80\x00\x00\x07", 4)

        int64_t pattern_offset = find_block(data, 0x50000, &task, 0x2A0000);
        if (pattern_offset == -1) {
            break;
        }

        uint64_t patch_addr = (int64_t)data + pattern_offset;

        //        printf("popnhax: found hidden chart (07) at %llx\n", patch_addr);
        patch_memory(patch_addr, (char *)"\x00\x00\x00\x07", 4);
        patched = true;
    }

    if (patched) {
        printf("popnhax: found and unlocked hidden charts (07)\n");
    }

    return patched;
}

static bool patch_unlock_classic8() {
    DWORD dllSize = 0;
    char *data = getDllData("popn22.dll", &dllSize);

    int64_t first_loc = 0;

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x10\xF1\x01\xF2\x01", 5)

        first_loc = find_block(data, dllSize, &task, 0);
        if (first_loc == -1) {
            return false;
        }
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x00\x05", 2)

        int64_t pattern_offset = find_block(data, 0x10, &task, first_loc);
        if (pattern_offset != -1) {
            uint64_t patch_addr = (int64_t)data + pattern_offset;
            patch_memory(patch_addr, (char *)"\x00\x07", 2);
        }
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x26\x01", 2)

        int64_t pattern_offset = find_block(data, 0x20, &task, first_loc);
        if (pattern_offset != -1) {
            uint64_t patch_addr = (int64_t)data + pattern_offset;
            patch_memory(patch_addr, (char *)"\x26\x31", 2);

            printf("popnhax: classic 8 EX (49) unlocked\n");
        }
    }

    return true;
}

static bool patch_unlock_all() {
    DWORD dllSize = 0;
    char *data = getDllData("popn22.dll", &dllSize);

    int64_t first_loc = 0;

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\xC3\x69\xC0\x34\x04", 5)

        first_loc = find_block(data, dllSize, &task, 0);
        if (first_loc == -1) {
            return false;
        }
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\xD0\x74", 2)

        int64_t pattern_offset = find_block(data, 0x60, &task, first_loc);
        if (pattern_offset != -1) {
            uint64_t patch_addr = (int64_t)data + pattern_offset;
            patch_memory(patch_addr, (char *)"\xD0\xEB", 2);
        }
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x83\xFE\x0A\x75", 4)

        int64_t pattern_offset = find_block(data, 0x80, &task, first_loc);
        if (pattern_offset != -1) {
            uint64_t patch_addr = (int64_t)data + pattern_offset;
            patch_memory(patch_addr, (char *)"\x83\xFE\x0A\x90\x90", 5);
        }
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x00\x08\x74", 3)

        int64_t pattern_offset = find_block(data, 0x90, &task, first_loc);
        if (pattern_offset != -1) {
            uint64_t patch_addr = (int64_t)data + pattern_offset;
            patch_memory(patch_addr, (char *)"\x00\x08\x90\x90", 4);
        }
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\xFF\xFF\xFF\x84\xC0\x74", 6)

        int64_t pattern_offset = find_block(data, 0x100, &task, first_loc);
        if (pattern_offset != -1) {
            uint64_t patch_addr = (int64_t)data + pattern_offset;
            patch_memory(patch_addr, (char *)"\xFF\xFF\xFF\xB0\x01\x74", 6);

            printf("popnhax: all songs and characters unlocked\n");
        }
    }

    return true;
}

static bool patch_skip_tutorials() {
    DWORD dllSize = 0;
    char *data = getDllData("popn22.dll", &dllSize);

    int64_t first_loc = 0;

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\xFD\xFF\x5E\xC2\x04\x00\xE8", 7)

        first_loc = find_block(data, dllSize, &task, 0);
        if (first_loc == -1) {
            return false;
        }
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x74", 1)

        int64_t pattern_offset = find_block(data, 0x10, &task, first_loc);
        if (pattern_offset == -1) {
            return false;
        }

        uint64_t patch_addr = (int64_t)data + pattern_offset;
        patch_memory(patch_addr, (char *)"\xEB", 1);
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x66\x85\xC0\x75\x5E\x6A", 6)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
            return false;
        }

        uint64_t patch_addr = (int64_t)data + pattern_offset;
        patch_memory(patch_addr, (char *)"\x66\x85\xC0\xEB\x5E\x6A", 6);
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x00\x5F\x5E\x66\x83\xF8\x01\x75", 8)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
            return false;
        }

        uint64_t patch_addr = (int64_t)data + pattern_offset;
        patch_memory(patch_addr, (char *)"\x00\x5F\x5E\x66\x83\xF8\x01\xEB", 8);
    }

    printf("popnhax: menu and long note tutorials skipped\n");

    return true;
}

uint64_t *g_rend_addr;
uint64_t *font_color;
uint64_t *font_rend_func;

const char stats_disp_header[] = " - HELLO WORLD - ";
const char stats_disp_format[] = "%s";
void enhanced_polling_stats_disp_sub()
{
    __asm("mov r9, %0\n"::"a"(stats_disp_header));  //varg
    __asm("mov r8, %0\n"::"a"(stats_disp_format));  // format
    __asm("mov rdx, 0x2A\n");                        // Y coord
    __asm("mov rcx, 0x160\n");                       // X coord
//__asm("mov esi, %0\n"::"a"(*font_color+COLOR_LIGHT_GREY));
    __asm("call %0\n"::"a"(font_rend_func));
//__asm("add esp, 0x0C\n");
}

void (*real_render_loop)();
void enhanced_polling_stats_disp()
{
    __asm("mov eax, [%0]\n"::"a"(g_rend_addr));
    __asm("cmp byte ptr [eax], 0\n");
    __asm("je call_stat_menu\n");
    __asm("mov dword ptr [eax], 2\n");
    __asm("mov dword ptr [eax+4], 0\n"); //1
    //__asm("mov dword ptr [eax+8], 0\n");
    __asm("mov dword ptr [eax+0x34], 1\n");

    __asm("call_stat_menu:\n");
    enhanced_polling_stats_disp_sub();
    real_render_loop();
}

static bool patch_enhanced_polling_stats() {
    DWORD dllSize = 0;
    char *data = getDllData("popn.dll", &dllSize);

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x4C\x89\x44\x24\x18\x4C\x89\x4C\x24\x20\x53\x55\x56\x57\x41\x56\x48\x83", 18)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
            return false;
        }

        font_rend_func = (uint64_t *)((uint64_t)data + pattern_offset);
        LOG("popnhax: get_rendaddr: font_rend_func is 0x%llX\n", (uint64_t)font_rend_func);
    }
    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x48\x8B\x05\xE5\x3C\xCF\x00", 7)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
            return false;
        }

	//LOG("found pattern at address 0x%llX\n", (uint64_t)data+pattern_offset+7+);
        g_rend_addr = (uint64_t *)((uint64_t)data + pattern_offset + 7 + 0xCF3CE5);
        LOG("popnhax: get_rendaddr: g_rend_addr is 0x%llX\n", (uint64_t)g_rend_addr);
    }

    {
        fuzzy_search_task task;

        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x48\x81\xEC\x98\x00\x00\x00\x48\x8B\x05\xD2\x1B", 12)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
	    LOG("popnhax: cannot find AGING loop");
            return false;
        }

        uint64_t patch_addr = (uint64_t)data + pattern_offset + 7;
        MH_CreateHook((LPVOID)patch_addr, (LPVOID)enhanced_polling_stats_disp,
                      (void **)&real_render_loop);
	LOG("popnhax: hook installed");
    }

    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        if (MH_Initialize() != MH_OK) {
            printf("Failed to initialize minhook\n");
            exit(1);
            return TRUE;
        }

        _load_config("popnhax.xml", &config, config_psmap);

	patch_enhanced_polling_stats();
        patch_get_time(1.);
	
        MH_EnableHook(MH_ALL_HOOKS);
Sleep(3000); // time to read the logs
        break;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
