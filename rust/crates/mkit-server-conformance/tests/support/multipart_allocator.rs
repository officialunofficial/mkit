//! Process-wide heap meter for one multipart case per nextest process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use mkit_server_conformance::storage::multipart::HeapProbe;

struct Meter;
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

unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            add(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(ptr, layout, size) };
        if !next.is_null() {
            if size >= layout.size() {
                add(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
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

pub(crate) fn probe() -> HeapProbe {
    HeapProbe { start, finish }
}
