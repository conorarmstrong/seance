//! Shared walk of a task's open file-descriptor table.
//!
//! Two stages need to iterate a process's `files->fdt->fd[]` array: `lsof`
//! (which reads every descriptor) and `sockstat` (which keeps only the sockets).
//! The navigation down to the array and the slot iteration — including the
//! corruption cap on `max_fds` and the `checked_mul` guard on each slot address
//! — is identical between them, and used to be copy-pasted (CR-005). It lives
//! here once; each caller supplies what to do per descriptor.

use seance_memory::binding::{BuildBinding, Field};
use seance_memory::object::{Obj, ObjError, StructReader};

use crate::error::StageError;

/// One descriptor slot handed to the per-fd callback.
pub enum FdSlot<'a> {
    /// A non-null slot: `filp` is the `struct file *` for descriptor `fd`.
    Open { fd: u64, filp: u64 },
    /// The slot pointer itself would not read; `err` explains why.
    Unreadable {
        fd: u64,
        slot: u64,
        err: &'a ObjError,
    },
}

/// The result of navigating down to (and iterating) the descriptor array,
/// before any per-fd work is interpreted. Callers map this onto their own
/// stage-specific outcome enum.
pub enum FdTableOutcome {
    /// The array was reached and every slot was visited.
    Walked,
    /// The task has no file table — a kernel thread or an exited task, not a gap.
    NoFileTable,
    /// The table, or one of the pointers on the way to it, would not read.
    Unreadable(String),
    /// `max_fds` exceeded the corruption cap; the array was not walked.
    Corrupt { max_fds: i64 },
}

/// Walk `task_obj`'s file-descriptor table, invoking `on_slot` once per
/// descriptor (both open slots and slots whose pointer would not read). Null
/// slots — closed descriptors — are skipped silently. Returns the navigation
/// outcome plus an optional loop note, set when a descriptor's address overflows
/// the address space (which stops the walk).
///
/// `on_slot` is a single callback rather than two so it can hold one mutable
/// borrow of whatever it accumulates into.
pub fn walk_fd_table(
    reader: &StructReader,
    layout: &BuildBinding,
    task_obj: &Obj,
    pointer_size: u64,
    max_fds_cap: u64,
    mut on_slot: impl FnMut(FdSlot) -> Result<(), StageError>,
) -> Result<(FdTableOutcome, Option<String>), StageError> {
    // The file table, or why there is none.
    let files_member = layout
        .member("files")?
        .member()
        .expect("a required member is declared or binding refused the stage");
    let files = match task_obj.follow(files_member) {
        Ok(Some(files)) => files,
        // A null file table is a kernel thread or an exited task — not a gap.
        Ok(None) => return Ok((FdTableOutcome::NoFileTable, None)),
        Err(err) => {
            return Ok((
                FdTableOutcome::Unreadable(format!(
                    "the task's file-table pointer could not be read: {err}"
                )),
                None,
            ))
        }
    };

    // The descriptor table.
    let fdt_member = layout
        .member("fdt")?
        .member()
        .expect("a required member is declared or binding refused the stage");
    let fdt = match files.follow(fdt_member) {
        Ok(Some(fdt)) => fdt,
        Ok(None) => {
            return Ok((
                FdTableOutcome::Unreadable(
                    "the file table's descriptor-table pointer is null".to_string(),
                ),
                None,
            ))
        }
        Err(err) => {
            return Ok((
                FdTableOutcome::Unreadable(format!(
                    "the descriptor-table pointer could not be read: {err}"
                )),
                None,
            ))
        }
    };

    let max_fds = match layout.read_unsigned(&fdt, "max_fds")? {
        Field::Known(value) => value,
        Field::Unavailable(detail) => return Ok((FdTableOutcome::Unreadable(detail), None)),
        Field::NotApplicable | Field::NotDeclared { .. } => {
            return Ok((
                FdTableOutcome::Unreadable(
                    "the descriptor table's size could not be established".to_string(),
                ),
                None,
            ))
        }
    };
    if max_fds > max_fds_cap {
        return Ok((
            FdTableOutcome::Corrupt {
                max_fds: max_fds as i64,
            },
            None,
        ));
    }

    let fd_base = match layout.read_pointer(&fdt, "fd")? {
        Field::Known(0) => {
            return Ok((
                FdTableOutcome::Unreadable(
                    "the descriptor table's open-file array pointer is null".to_string(),
                ),
                None,
            ))
        }
        Field::Known(address) => address,
        Field::Unavailable(detail) => return Ok((FdTableOutcome::Unreadable(detail), None)),
        Field::NotApplicable | Field::NotDeclared { .. } => {
            return Ok((
                FdTableOutcome::Unreadable(
                    "the descriptor table has no readable open-file array".to_string(),
                ),
                None,
            ))
        }
    };

    let mut loop_note = None;
    for fd in 0..max_fds {
        let Some(slot) = fd
            .checked_mul(pointer_size)
            .and_then(|offset| fd_base.checked_add(offset))
        else {
            loop_note = Some(format!(
                "the address of fd {fd} does not fit in the address space"
            ));
            break;
        };
        let filp = match reader.read_pointer_at(slot) {
            Ok(value) => value,
            Err(err) => {
                on_slot(FdSlot::Unreadable {
                    fd,
                    slot,
                    err: &err,
                })?;
                continue;
            }
        };
        // A null slot is a closed descriptor: skipped, not a gap.
        if filp == 0 {
            continue;
        }
        on_slot(FdSlot::Open { fd, filp })?;
    }

    Ok((FdTableOutcome::Walked, loop_note))
}
