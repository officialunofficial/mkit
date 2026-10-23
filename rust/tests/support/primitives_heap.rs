//! Test-only meter of Rust allocator requests, excluding pre-acquired host input.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn account(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::SeqCst) + size;
    PEAK.fetch_max(live, Ordering::SeqCst);
}

// SAFETY: forward the exact pointer and layout to System. The atomics observe
// requested bytes only; they never alter allocation or ownership semantics.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: layout comes straight from the GlobalAlloc caller, so System upholds its contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            account(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: layout comes straight from the GlobalAlloc caller, so System upholds its contract.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            account(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        // SAFETY: ptr and layout come from the caller of dealloc, per the GlobalAlloc contract.
        unsafe { System.dealloc(pointer, layout) };
    }
}

/// One allocation epoch in a dedicated, single-test binary. This measures Rust
/// requested live bytes, including freed transient buffers, not C allocations,
/// allocator metadata, stack frames, or whole-process resident memory.
pub(crate) struct Epoch {
    baseline: usize,
}
impl Epoch {
    pub(crate) fn begin() -> Self {
        let baseline = LIVE.load(Ordering::SeqCst);
        PEAK.store(baseline, Ordering::SeqCst);
        Self { baseline }
    }
    pub(crate) fn live(&self) -> u64 {
        LIVE.load(Ordering::SeqCst).saturating_sub(self.baseline) as u64
    }
    pub(crate) fn peak(&self) -> u64 {
        PEAK.load(Ordering::SeqCst).saturating_sub(self.baseline) as u64
    }
}
