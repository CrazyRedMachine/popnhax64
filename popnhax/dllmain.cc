// clang-format off
#include <windows.h>
#include <psapi.h>
#include <process.h>
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
        FUZZY_CODE(task, 0, "\x48\x8B\x7B\x10\x48\x8B\xCF\xE8\xB5", 9)
	//FUZZY_CODE(task, 0, "\x48\x81\xEC\x98\x00\x00\x00\x48\x8B\x05\xD2\x1B", 12)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
	    LOG("popnhax: cannot find AGING loop");
            return false;
        }

        uint64_t patch_addr = (uint64_t)data + pattern_offset - 9;
        //uint64_t patch_addr = (uint64_t)data + pattern_offset + 7;
        MH_CreateHook((LPVOID)patch_addr, (LPVOID)enhanced_polling_stats_disp,
                      (void **)&real_render_loop);
	LOG("popnhax: hook installed");
    }

    return true;
}

struct AIO_IOB5_BI3A {
    uint8_t data[0x4FF0];
};

union AIO_IOB5_BI3A__DEVSTATUS {
    uint8_t RawBytes[648];
    struct {
        uint8_t Reserved0[27];  // 0-26
        uint8_t Coin0;          // 27
        uint8_t Coin1;          // 28
        uint8_t Reserved1[15];  // 29-43
        uint8_t TestButton;     // 44, io code offset rcx+0xe4
        uint8_t ServiceButton;  // 45, io code offset rcx+0xe5
        uint8_t CoinMech;       // 46, io code offset rcx+0xe6
        uint8_t Reserved2[19];  // 47-65
        uint8_t JOYL_SW;        // 66
        uint8_t Reserved3[4];   // 67-70
        uint8_t JOYR_SW;        // 71
        uint8_t Headphones;     // 72
        uint8_t Recorder;       // 73, unused
        uint8_t Reserved4[295]; // 74-368
        uint16_t Buttons;    // 369
    } Input;
};

volatile uint8_t g_enhanced_poll_ready = 0;
AIO_IOB5_BI3A *g_BI3A = NULL;
AIO_IOB5_BI3A__DEVSTATUS *g_BI3A_STATUS = NULL;

void (__fastcall *mGetDeviceStatus)(AIO_IOB5_BI3A *,AIO_IOB5_BI3A__DEVSTATUS*) = NULL;

uint32_t g_poll_rate_avg = 0;
uint32_t g_last_button_state = 0;
uint8_t g_debounce = 0;
int32_t g_button_state[9] = {0};
static unsigned int __stdcall enhanced_polling_proc(void *ctx)
{
    HMODULE hinstLib = GetModuleHandleA("libaio-iob5.dll");
    //mGetDeviceStatus = (void(*)(AIO_IOB5_BI3A *,AIO_IOB5_BI3A__DEVSTATUS*))GetProcAddress(hinstLib, "?GetDeviceStatus@AIO_IOB5_BI3A@@QEBAXAEAUDEVSTATUS@1@@Z");
    mGetDeviceStatus = (void(*)(AIO_IOB5_BI3A *,AIO_IOB5_BI3A__DEVSTATUS*))GetProcAddress(hinstLib, "aioIob5Bi3a_GetDeviceStatus");
    static uint8_t button_debounce[9] = {0};
printf("POLLING THREAD RUNNING\n");
    for (int i=0; i<9; i++)
    {
        g_button_state[i] = -1;
    }

    while (!g_enhanced_poll_ready)
    {
        Sleep(500);
    }
/*
    if (config.enhanced_polling_priority)
    {
        SetThreadPriority(GetCurrentThread(), config.enhanced_polling_priority);
        LOG("[Enhanced polling] Thread priority set to %d\n", GetThreadPriority(GetCurrentThread()));
    }
*/
    uint32_t curr_poll_time = 0;
    uint32_t prev_poll_time = 0;
    while (g_enhanced_poll_ready)
    {
        //uint32_t pad_bits;
        /* ensure at least 1ms has elapsed between polls
         * (beware of SD cab hardware compatibility)
         */
        curr_poll_time = timeGetTime();
        if (curr_poll_time == prev_poll_time)
        {
            curr_poll_time++;
            Sleep(1);
        }
        prev_poll_time = curr_poll_time;

        mGetDeviceStatus(g_BI3A, g_BI3A_STATUS);

        g_last_button_state = g_BI3A_STATUS->Input.Buttons;

        unsigned int buttonState = (g_last_button_state) & 0x1FF;
        for (int i = 0; i < 9; i++)
        {
            if ( ((buttonState >> i)&1) )
            {
                if (g_button_state[i] == -1)
                {
                    g_button_state[i] = curr_poll_time;
                }
                //debounce on release (since we're forced to stub usbPadReadLast)
                button_debounce[i] = g_debounce;
            }
            else
            {
                if (button_debounce[i]>0)
                {
                    button_debounce[i]--;
                }

                if (button_debounce[i] == 0)
                {
                    g_button_state[i] = -1;
                }
                else
                {
                    //debounce ongoing: flag button as still pressed
                    g_last_button_state |= 1<<(i);
                }
            }
        }
    }
    return 0;
}

/*
on hook juste après le mov dans esi ( 45 32 FF .43 8B 74 D1 08 + 0x08 )
-> RDX contient le num du bouton (0-index), ESI le delta à compenser 
=> soustraire à esi la valeur de g_sincewhen[rdx]) /!\ si et seulement si esi != 0x400 /!\
*/
uint32_t buttonGetMillis(uint8_t button)
{
    if (g_button_state[button] == -1)
        return 0;

    uint32_t but = g_button_state[button];
    uint32_t curr = timeGetTime();
    if (but <= curr)
    {
        uint32_t res = curr - but;
        return res;
    }

    return 0;
}

uint32_t g_offset_fix[9] = {0};
uint8_t g_poll_index = 0;
void (*real_timing_eval)();
void enhanced_polling_hook_timing_eval() {
    /* eax contains button being checked [0-8] -> RDX mtn
     * esi contains delta about to be evaluated 
     * we need to do esi -= buttonGetMillis([%eax]); -> %rdx to fix the offset accurately */
    __asm("push rbx\n");

    __asm("mov %0, dl\n":"=m"(g_poll_index): :);

    /* reimplem buttonGetMillis(), result in ebx */
    __asm("xor ebx,ebx\n");
    __asm("mov edx,dword ptr ds:[rdx*4+%0]\n"::"a"(g_button_state));
    __asm("cmp edx,0xFFFFFFFF\n");
    __asm("je button_state_empty\n");

    __asm("push rcx\n");
    __asm("push rdx\n");
    __asm("call %P0" : : "d"(timeGetTime));
    __asm("pop rdx\n");
    __asm("pop rcx\n");
    __asm("cmp edx,eax\n");

    __asm("jbe button_has_been_pressed\n");

    __asm("restore_rdx:\n");
    __asm("movzx rdx, %0\n": :"d"(g_poll_index));

    /* leave buttonGetMillis */
    __asm("button_state_empty:\n");
    __asm("sub esi, ebx\n"); // actual delta correction
    __asm("mov rdx, rcx\n");
    __asm("lea rax,dword ptr [rdx*4+%0]\n"::"a"(g_offset_fix));
    __asm("mov [rax], ebx\n"::); // save correction value in g_offset_fix[g_poll_index];

    __asm("pop rbx\n");
	__asm("mov rax, %0\n" : : "m"(real_timing_eval));
    __asm("jmp rax");

    __asm("button_has_been_pressed:\n");
    __asm("sub eax,edx\n"); // eax = correction value (currTime - g_button_state[g_poll_index]);
    __asm("mov ebx, eax\n");// put correction value in ebx
    __asm("jmp restore_rdx\n");
}

void (*real_getdevicestatus_call)();
void enhanced_polling_hook_getdevicestatus_call()
{
    //__asm("cmp byte ptr[_g_enhanced_poll_ready], 1");
    if ( g_enhanced_poll_ready )
        __asm("jmp skip_getdevicestatus_call");

    __asm("mov %0, rcx":"=m"(g_BI3A):);
    __asm("mov %0, rdx":"=m"(g_BI3A_STATUS):);
    g_enhanced_poll_ready = 1;
    //__asm("mov %0, 0x01\n":"=m"(g_enhanced_poll_ready):);
    __asm("skip_getdevicestatus_call:\n");
	//memcpy( g_BI3A_STATUS, g_int_status, 648*sizeof(uint8_t));
	__asm("mov rax, 0\n");
    __asm("ret 0\n");
}

static HANDLE enhanced_polling_thread;

static bool patch_enhanced_polling_prep() {
    DWORD dllSize = 0;
    char *data = getDllData("popn.dll", &dllSize);

    {
        fuzzy_search_task task;
        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x49\x08\x48\xFF\x25\xA6\xAF\x16\x00", 9)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
        LOG("popnhax: cannot find GetDeviceStatus call");
            return false;
        }

        uint64_t patch_addr = (uint64_t)data + pattern_offset + 0x02;
        MH_CreateHook((LPVOID)patch_addr, (LPVOID)enhanced_polling_hook_getdevicestatus_call,
                      (void **)&real_getdevicestatus_call);
    }

    {
        fuzzy_search_task task;
        FUZZY_START(task, 1)
        FUZZY_CODE(task, 0, "\x45\x32\xFF\x43\x8B\x74\xD1\x08", 8)

        int64_t pattern_offset = find_block(data, dllSize, &task, 0);
        if (pattern_offset == -1) {
        LOG("popnhax: cannot find timing eval function");
            return false;
        }

        uint64_t patch_addr = (uint64_t)data + pattern_offset + 0x08;
        MH_CreateHook((LPVOID)patch_addr, (LPVOID)enhanced_polling_hook_timing_eval,
                      (void **)&real_timing_eval);
    }

    LOG("popnhax: enhanced polling hooks installed");
    enhanced_polling_thread = (HANDLE) _beginthreadex(NULL, 0, enhanced_polling_proc, NULL, 0, NULL);
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
	patch_enhanced_polling_prep();
	
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
