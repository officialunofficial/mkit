//! Heap meter with per-allocation provenance, so in-process bucket bytes do
//! not count even if another thread eventually frees them.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use mkit_server_conformance::storage::multipart::HeapProbe;

thread_local! { static EXCLUDED: Cell<bool> = const { Cell::new(false) }; }

pub fn exclude_current_thread() {
    EXCLUDED.with(|excluded| excluded.set(true));
}

struct Meter;
#[repr(C)]
struct Header {
    size: usize,
    offset: usize,
    align: usize,
    counted: bool,
}
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);
static MEASURING: AtomicBool = AtomicBool::new(false);

#[global_allocator]
static ALLOCATOR: Meter = Meter;

fn add(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed).saturating_add(size);
    if MEASURING.load(Ordering::Relaxed) {
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

#[allow(clippy::cast_ptr_alignment)] // System allocates the base at max(layout, Header) alignment.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let offset = size_of::<Header>().div_ceil(layout.align()) * layout.align();
        let align = layout.align().max(align_of::<Header>());
        let Some(size) = offset.checked_add(layout.size()) else {
            return ptr::null_mut();
        };
        let Ok(whole) = Layout::from_size_align(size, align) else {
            return ptr::null_mut();
        };
        let base = unsafe { System.alloc(whole) };
        if base.is_null() {
            return base;
        }
        let counted = !EXCLUDED.try_with(Cell::get).unwrap_or(false);
        unsafe {
            base.cast::<Header>().write(Header {
                size: layout.size(),
                offset,
                align,
                counted,
            });
        }
        if counted {
            add(layout.size());
        }
        unsafe { base.add(offset) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        // The offset is stored at the base. Read it from the fixed header
        // immediately before the returned pointer's alignment padding.
        // Header location is recovered from the original layout alignment.
        let offset = size_of::<Header>().div_ceil(layout.align()) * layout.align();
        let base = unsafe { ptr.sub(offset) };
        let header = unsafe { base.cast::<Header>().read() };
        if header.counted {
            LIVE.fetch_sub(header.size, Ordering::Relaxed);
        }
        let whole =
            unsafe { Layout::from_size_align_unchecked(header.offset + header.size, header.align) };
        unsafe {
            System.dealloc(base, whole);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let Ok(next_layout) = Layout::from_size_align(size, layout.align()) else {
            return ptr::null_mut();
        };
        let next = unsafe { self.alloc(next_layout) };
        if !next.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(ptr, next, layout.size().min(size));
                self.dealloc(ptr, layout);
            }
        }
        next
    }
}

fn start() {
    MEASURING.store(false, Ordering::SeqCst);
    let baseline = LIVE.load(Ordering::SeqCst);
    BASELINE.store(baseline, Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    MEASURING.store(true, Ordering::SeqCst);
}

fn finish() -> usize {
    MEASURING.store(false, Ordering::SeqCst);
    PEAK.load(Ordering::SeqCst)
        .saturating_sub(BASELINE.load(Ordering::SeqCst))
}

pub fn probe() -> HeapProbe {
    HeapProbe { start, finish }
}
