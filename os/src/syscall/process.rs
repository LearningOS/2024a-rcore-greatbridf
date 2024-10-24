//! Process management syscalls
use core::mem::MaybeUninit;

use alloc::{boxed::Box, vec::Vec};

use crate::{
    config::MAX_SYSCALL_NUM,
    mm::{translate_validate, MapPermission, VirtAddr},
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, with_current_tcb, TaskStatus,
    },
    timer::{get_time_ms, get_time_us},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

fn copy_to_buffers<T: Sized>(data: &T, buffers: Vec<&'static mut [u8]>) {
    let buffers_len = buffers.iter().map(|b| b.len()).sum::<usize>();
    assert_eq!(buffers_len, core::mem::size_of::<T>());

    let mut pdata = data as *const T as *const u8;
    for buffer in buffers {
        let data = unsafe { core::slice::from_raw_parts(pdata, buffer.len()) };
        buffer.copy_from_slice(data);

        pdata = unsafe { pdata.add(buffer.len()) };
    }
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    let buffers = translate_validate(
        current_user_token(),
        _ts as *const _,
        core::mem::size_of::<TimeVal>(),
    );

    if buffers.is_none() {
        assert!(false);
        return -1;
    }

    let buffers = buffers.unwrap();

    let mut cur_time = TimeVal { sec: 0, usec: 0 };

    let cur_time_us = get_time_us();
    cur_time.sec = cur_time_us / 1_000_000;
    cur_time.usec = cur_time_us % 1_000_000;

    copy_to_buffers(&cur_time, buffers);

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info!");
    let mut info: Box<MaybeUninit<TaskInfo>> = Box::new(MaybeUninit::zeroed());

    with_current_tcb(|current| {
        let info = unsafe { info.assume_init_mut() };
        info.status = current.task_status;
        info.syscall_times = current.syscall_times;
        info.time = get_time_ms() - current.time.expect("sys_task_info: wtf");
    });

    let buffers = translate_validate(
        current_user_token(),
        _ti as *const _,
        core::mem::size_of::<TaskInfo>(),
    );

    if buffers.is_none() {
        return -1;
    }
    let buffers = buffers.unwrap();

    copy_to_buffers(unsafe { info.assume_init_ref() }, buffers);

    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap, tid: {}", current_user_token());
    let start = VirtAddr::from(_start);
    let end = VirtAddr::from(_start + _len);

    if !start.aligned() {
        return -1;
    }

    if _port & !0x7 != 0 {
        return -1;
    }

    let flag: MapPermission =
        MapPermission::from_bits_truncate((_port << 1) as u8) | MapPermission::U;

    with_current_tcb(|current| {
        let mms = current.get_mm_set();
        mms.mmap_checked(start, end, flag)
    }).map_or(-1, |_| 0)
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap, tid: {}", current_user_token());
    let start = VirtAddr::from(_start);
    let end = VirtAddr::from(_start + _len);

    if !start.aligned() {
        return -1;
    }

    trace!("munmap: _start: {:x}, _len: {:x}", _start, _len);
    trace!("munmap: start: {:?}, end: {:?}", start.floor(), end.ceil());

    with_current_tcb(|current| {
        let mms = current.get_mm_set();
        mms.unmap_checked(start, end)
    })
    .map_or(-1, |_| 0)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
