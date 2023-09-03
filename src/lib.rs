use std::{arch::asm, ffi::c_void, mem::transmute};

use rand::{rngs::ThreadRng, Rng};
use windows::{
    core::{s, HSTRING, PCWSTR},
    Win32::{
        Foundation::{FARPROC, HINSTANCE, HMODULE, MAX_PATH},
        Graphics::Direct3D9::IDirect3D9,
        System::{
            Console::AllocConsole,
            LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW},
            Memory::{VirtualProtect, PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS},
            ProcessStatus::{GetModuleInformation, MODULEINFO},
            SystemInformation::GetSystemDirectoryW,
            SystemServices::DLL_PROCESS_ATTACH,
            Threading::GetCurrentProcess,
        },
    },
};

static mut BASE_ADDR: usize = 0;
static mut ORIGINAL_DIRECT_3D_CREATE_9: FARPROC = None;
static mut ORIGINAL_FN_00ABF0: *mut c_void = 0 as _;
static mut STAGE_CHARACTER: i32 = 0;
static mut STAGE: i32 = 0;
static mut RNG: Option<ThreadRng> = None;

unsafe fn rng() -> &'static mut ThreadRng {
    RNG.as_mut().unwrap()
}

fn load_library(dll_name: &str) -> HMODULE {
    let system_directory = unsafe {
        let mut buf = [0u16; MAX_PATH as usize];
        GetSystemDirectoryW(Some(&mut buf));
        PCWSTR::from_raw(buf.as_ptr()).to_string().unwrap()
    };
    let dll_path = format!("{}\\{}", system_directory, dll_name);
    let dll_instance = unsafe { LoadLibraryW(&HSTRING::from(dll_path)) }.unwrap();
    if dll_instance.is_invalid() {
        panic!();
    }
    dll_instance
}

fn setup() {
    let dll_instance = load_library("d3d9.dll");
    let func = unsafe { GetProcAddress(dll_instance, s!("Direct3DCreate9")) };
    unsafe { ORIGINAL_DIRECT_3D_CREATE_9 = Some(func.unwrap()) };
    unsafe { RNG = Some(rand::thread_rng()) };
}

#[no_mangle]
pub extern "stdcall" fn DllMain(
    _inst_dll: HINSTANCE,
    reason: u32,
    _reserved: *const c_void,
) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        setup();
        if cfg!(debug_assertions) {
            unsafe { AllocConsole() }.unwrap();
        }
    }
    true
}

fn get_process_base_address() -> usize {
    let mut module_info: MODULEINFO = Default::default();
    let h_process = unsafe { GetCurrentProcess() };
    let cb_needed = std::mem::size_of::<MODULEINFO>() as u32;
    unsafe {
        GetModuleInformation(
            h_process,
            GetModuleHandleW(&HSTRING::from("th19.exe")).unwrap(),
            &mut module_info as *mut MODULEINFO,
            cb_needed,
        )
    }
    .unwrap();
    module_info.lpBaseOfDll as usize
}

unsafe fn tamper_near_jmp_opr(addr: usize, target: usize) -> usize {
    let jump_base_addr = addr + 5;
    let jump_ref_addr = (addr + 1) as *mut i32;
    let old = (jump_base_addr as i64 + *jump_ref_addr as i64) as usize;
    *jump_ref_addr = (target as i64 - jump_base_addr as i64) as i32;
    old
}

extern "fastcall" fn hook_00abf0(obj: *mut c_void) -> i32 {
    type Func = extern "fastcall" fn(obj: *mut c_void) -> u32;
    let func: Func = unsafe { transmute(ORIGINAL_FN_00ABF0) };
    func(obj);
    unsafe { rng() }.gen_range(0..19)
}

extern "fastcall" fn hook_105b7a() -> i32 {
    let mut old: i32;
    unsafe {
        asm!(
            "mov {old}, eax",
            old = out(reg) old,
        )
    };

    let first_round = unsafe { *((BASE_ADDR + 0x2078fc) as *const i32) } & 0x02 == 0;

    if first_round {
        let stage_character = unsafe { rng() }.gen_range(0..19);
        unsafe { STAGE_CHARACTER = stage_character };
        println!("{} -> {}", old, stage_character);
    }
    let stage_character = unsafe { STAGE_CHARACTER };

    // NOPed processes
    unsafe { *((BASE_ADDR + 0x2082D0) as *mut u32) = 0xffffffff };
    stage_character << 5
}

#[allow(unused)]
unsafe fn assemble_105b79(base_addr: usize) {
    *((base_addr + 0x105B79) as *mut u8) = 0xe8; // call
    tamper_near_jmp_opr(base_addr + 0x105B79, hook_105b7a as _);
    for i in 0..8 {
        *((base_addr + 0x105B7E + i) as *mut u8) = 0x90; // nop
    }
}

extern "fastcall" fn hook_105b90() {
    let mut eax: usize;
    unsafe {
        asm!(
            "mov {eax}, eax",
            eax = out(reg) eax,
        )
    };

    let old = unsafe { *((BASE_ADDR + 0x1a2b90 + eax) as *const i32) };
    let first_round = unsafe { *((BASE_ADDR + 0x2078fc) as *const i32) } & 0x02 == 0;
    if first_round {
        let stage = unsafe { rng() }.gen_range(0..17);
        unsafe { STAGE = stage };
        println!("{} -> {}", old, stage);
    }
    let stage = unsafe { STAGE };

    unsafe {
        asm!(
            "mov ecx, {stage}",
            stage = in(reg) stage,
        )
    };
}

unsafe fn assemble_105b90(base_addr: usize) {
    *((base_addr + 0x105b90) as *mut u8) = 0xe8; // call
    tamper_near_jmp_opr(base_addr + 0x105b90, hook_105b90 as _);
    *((base_addr + 0x105b95) as *mut u8) = 0x90; // nop
}

#[no_mangle]
extern "stdcall" fn Direct3DCreate9(sdkversion: u32) -> *const IDirect3D9 {
    let base_addr = get_process_base_address();
    unsafe { BASE_ADDR = base_addr };

    unsafe {
        let mut old: PAGE_PROTECTION_FLAGS = Default::default();
        VirtualProtect(
            (base_addr + 0x105bb0) as _,
            0x002000,
            PAGE_EXECUTE_WRITECOPY,
            &mut old,
        )
        .unwrap();
        ORIGINAL_FN_00ABF0 = tamper_near_jmp_opr(base_addr + 0x1065F4, hook_00abf0 as _) as _;

        assemble_105b90(base_addr);

        VirtualProtect((base_addr + 0x105bb0) as _, 0x2000, old, &mut old).unwrap();
    }

    type Func = extern "stdcall" fn(sdkversion: u32) -> *const IDirect3D9;
    let func: Func = unsafe { transmute(ORIGINAL_DIRECT_3D_CREATE_9) };
    func(sdkversion)
}
