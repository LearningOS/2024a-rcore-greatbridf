//! File and filesystem-related syscalls
use crate::fs::{get_root_inode, open_file, OpenFlags, Stat};
use crate::mm::{
    translated_byte_buffer, translated_byte_iterator, translated_str, MapPermission, UserBuffer,
    VirtAddr,
};
use crate::task::{current_check_access, current_task, current_user_token};

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_write", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.write(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_read", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        if !file.readable() {
            return -1;
        }
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        trace!("kernel: sys_read .. file.read");
        file.read(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    trace!("kernel:pid[{}] sys_open", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(inode) = open_file(path.as_str(), OpenFlags::from_bits(flags).unwrap()) {
        let mut inner = task.inner_exclusive_access();
        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode);
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    trace!("kernel:pid[{}] sys_close", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.fd_table[fd].take();
    0
}

/// YOUR JOB: Implement fstat.
pub fn sys_fstat(fd: usize, st: *mut Stat) -> isize {
    trace!("kernel:pid[{}] sys_fstat", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }

    let start = VirtAddr::from(st as usize);
    let end = VirtAddr::from(st as usize + core::mem::size_of::<Stat>());

    if current_check_access(start, end, MapPermission::W | MapPermission::U).is_err() {
        return -1;
    }

    if let Some(file) = &inner.fd_table[fd] {
        let mut stat = Stat::default();
        file.stat(&mut stat);

        let buffer = translated_byte_iterator(token, st as *const _, core::mem::size_of::<Stat>());
        write_object(buffer, &stat);

        0
    } else {
        -1
    }
}

/// YOUR JOB: Implement linkat.
pub fn sys_linkat(old_name: *const u8, new_name: *const u8) -> Result<(), ()> {
    trace!("kernel:pid[{}] sys_linkat", current_task().unwrap().pid.0);
    let token = current_user_token();

    // ignore possible ESEGV
    let old_name = translated_str(token, old_name);
    let new_name = translated_str(token, new_name);

    // assume that pwd is fs root
    let pwd = get_root_inode();
    let old_inode = pwd.find(&old_name).ok_or(())?;

    pwd.link(&old_inode, &new_name).ok_or(()).map(|_| ())
}

/// YOUR JOB: Implement unlinkat.
pub fn sys_unlinkat(name: *const u8) -> Result<(), ()> {
    trace!("kernel:pid[{}] sys_unlinkat", current_task().unwrap().pid.0);
    let token = current_user_token();

    // ignore possible ESEGV
    let name = translated_str(token, name);

    // assume that pwd is fs root
    let pwd = get_root_inode();
    pwd.find(&name).ok_or(())?;
    pwd.unlink(&name);

    Ok(())
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
