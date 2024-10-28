//! Process management syscalls
use core::mem::MaybeUninit;

use alloc::{boxed::Box, sync::Arc};

use crate::{
    config::MAX_SYSCALL_NUM,
    loader::get_app_data_by_name,
    mm::{translated_byte_iterator, translated_refmut, translated_str, MapPermission, VirtAddr},
    task::{
        add_task, current_check_access, current_task, current_user_token,
        exit_current_and_run_next, suspend_current_and_run_next, TaskControlBlock, TaskStatus,
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

/// Write data to the given iterator and consume the iterator
///
/// # Return
/// The number of bytes actually written
fn write_bytes<'a>(iter: impl Iterator<Item = &'a mut u8>, data: &[u8]) -> usize {
    let mut written = 0;
    for (dst, src) in iter.zip(data.iter()) {
        *dst = *src;
        written += 1;
    }

    written
}

/// Write data to the given iterator and consume the iterator
fn write_object<'a, T: Sized>(iter: impl Iterator<Item = &'a mut u8>, object: &T) {
    let data = unsafe {
        core::slice::from_raw_parts((object as *const T) as *const u8, core::mem::size_of::<T>())
    };

    assert_eq!(write_bytes(iter, data), data.len());
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!(
        "kernel::pid[{}] sys_waitpid [{}]",
        current_task().unwrap().pid.0,
        pid
    );
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel:pid[{}] sys_get_time", current_task().unwrap().pid.0);
    let start = VirtAddr::from(_ts as usize);
    let end = VirtAddr::from((_ts as usize) + core::mem::size_of::<TimeVal>());

    if current_check_access(start, end, MapPermission::W | MapPermission::U).is_err() {
        return -1;
    }

    let mut cur_time = TimeVal { sec: 0, usec: 0 };

    let cur_time_us = get_time_us();
    cur_time.sec = cur_time_us / 1_000_000;
    cur_time.usec = cur_time_us % 1_000_000;

    write_object(
        translated_byte_iterator(
            current_user_token(),
            _ts as *const _,
            core::mem::size_of::<TimeVal>(),
        ),
        &cur_time,
    );

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");
    let start = VirtAddr::from(_ti as usize);
    let end = VirtAddr::from((_ti as usize) + core::mem::size_of::<TimeVal>());

    if current_check_access(start, end, MapPermission::W | MapPermission::U).is_err() {
        return -1;
    }

    let mut info: Box<MaybeUninit<TaskInfo>> = Box::new(MaybeUninit::zeroed());

    let current = current_task().unwrap();
    let current = current.inner_exclusive_access();

    {
        let info = unsafe { info.assume_init_mut() };
        info.status = current.task_status;
        info.syscall_times = current.syscall_times;
        info.time = get_time_ms() - current.time_start.expect("sys_task_info: wtf");
    }

    let byte_iter = translated_byte_iterator(
        current_user_token(),
        _ti as *const _,
        core::mem::size_of::<TaskInfo>(),
    );

    write_object(byte_iter, &info);

    0
}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel:pid[{}] sys_mmap", current_task().unwrap().pid.0);

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

    let current = current_task().unwrap();
    let mut current = current.inner_exclusive_access();

    current
        .memory_set
        .mmap_checked(start, end, flag)
        .map_or(-1, |_| 0)
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel:pid[{}] sys_munmap", current_task().unwrap().pid.0);

    let start = VirtAddr::from(_start);
    let end = VirtAddr::from(_start + _len);

    if !start.aligned() {
        return -1;
    }

    trace!("munmap: _start: {:x}, _len: {:x}", _start, _len);
    trace!("munmap: start: {:?}, end: {:?}", start.floor(), end.ceil());

    let current = current_task().unwrap();
    let mut current = current.inner_exclusive_access();

    current
        .memory_set
        .unmap_checked(start, end)
        .map_or(-1, |_| 0)
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(_path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_spawn", current_task().unwrap().pid.0);
    match (|| -> Result<_, ()> {
        let path = translated_str(current_user_token(), _path);
        let app = get_app_data_by_name(path.as_str()).ok_or(())?;

        let task = Arc::new(TaskControlBlock::new(app));

        let pid = task.pid.0;

        // add to child list
        let current = current_task().unwrap();
        current.inner_exclusive_access().children.push(task.clone());

        add_task(task);

        Ok(pid)
    })() {
        Ok(n) => n as isize,
        Err(err) => {
            trace!(
                "kernel:pid[{}] sys_spawn failed {:?}",
                current_task().unwrap().pid.0,
                err,
            );
            -1
        }
    }
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority",
        current_task().unwrap().pid.0
    );

    if _prio < 2 {
        return -1;
    }
    let prio = _prio as usize;

    current_task().unwrap().inner_exclusive_access().set_priority(prio);

    _prio
}
