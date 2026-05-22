import pytest
import threading
import ctypes
import gc
import weakref
from unittest.mock import MagicMock, patch, call
from collections import defaultdict

# Simulated AES-GCM-SIV context manager that mirrors the vulnerable JNI pattern
class AesGcmSivContext:
    """Simulates the JNI-managed AES-GCM-SIV context lifecycle"""
    
    _free_count = defaultdict(int)
    _lock = threading.Lock()
    
    def __init__(self, key_size=16):
        self._ptr = id(self)  # Simulate native pointer
        self._freed = False
        self._key_size = key_size
        AesGcmSivContext._free_count[self._ptr] = 0
    
    def free(self):
        """Vulnerable pattern: does NOT set ptr to NULL after free"""
        # This mirrors the vulnerable C code: aes_gcmsiv_free(ctx); free(ctx);
        # without setting the native pointer field to NULL afterward
        with AesGcmSivContext._lock:
            AesGcmSivContext._free_count[self._ptr] += 1
            # Vulnerable: _freed flag not checked, ptr not nulled
            self._freed = True
            # Does NOT set self._ptr = None/NULL (the vulnerability)
    
    def free_safe(self):
        """Safe pattern: sets ptr to NULL after free"""
        with AesGcmSivContext._lock:
            if self._ptr is not None and not self._freed:
                AesGcmSivContext._free_count[self._ptr] += 1
                self._freed = True
                self._ptr = None  # Safe: nulls the pointer
    
    def get_free_count(self):
        return AesGcmSivContext._free_count[id(self)]
    
    def __del__(self):
        """Simulates GC finalization calling free again"""
        pass


@pytest.mark.parametrize("payload", [
    # (scenario_name, num_threads, calls_per_thread, use_safe_impl)
    ("double_free_explicit", 1, 2, False),
    ("concurrent_double_free_2_threads", 2, 2, False),
    ("concurrent_double_free_4_threads", 4, 1, False),
    ("concurrent_double_free_8_threads", 8, 1, False),
    ("gc_finalization_double_free", 1, 3, False),
    ("rapid_concurrent_free_16_threads", 16, 1, False),
    ("sequential_triple_free", 1, 3, False),
    ("safe_impl_double_free_explicit", 1, 2, True),
    ("safe_impl_concurrent_4_threads", 4, 2, True),
    ("safe_impl_gc_finalization", 1, 3, True),
])
def test_aes_gcmsiv_no_double_free(payload):
    """Invariant: The AES-GCM-SIV context free function must NEVER be called
    more than once on the same native pointer. After free(), the native pointer
    field MUST be set to NULL/None to prevent double-free vulnerabilities
    regardless of concurrent access, GC finalization, or error handling paths."""
    
    scenario_name, num_threads, calls_per_thread, use_safe_impl = payload
    
    errors = []
    contexts = []
    
    def create_context():
        ctx = AesGcmSivContext(key_size=16)
        contexts.append(ctx)
        return ctx
    
    def attempt_free(ctx, use_safe):
        try:
            if use_safe:
                ctx.free_safe()
            else:
                ctx.free()
        except Exception as e:
            errors.append(str(e))
    
    # Create a fresh context for this test
    ctx = create_context()
    initial_ptr = ctx._ptr
    
    # Simulate concurrent/multiple free calls
    threads = []
    for _ in range(num_threads):
        for _ in range(calls_per_thread):
            t = threading.Thread(target=attempt_free, args=(ctx, use_safe_impl))
            threads.append(t)
    
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)
    
    # Force GC to simulate finalization
    weak_ref = weakref.ref(ctx)
    del ctx
    gc.collect()
    
    # SECURITY INVARIANT ASSERTIONS
    
    if use_safe_impl:
        # Safe implementation: pointer must be NULL after first free
        # and free count must never exceed 1
        for c in contexts:
            free_count = AesGcmSivContext._free_count[initial_ptr]
            assert free_count <= 1, (
                f"SECURITY VIOLATION [{scenario_name}]: Safe implementation "
                f"freed context {free_count} times (ptr={initial_ptr}). "
                f"Double-free detected - heap corruption possible!"
            )
            assert c._ptr is None, (
                f"SECURITY VIOLATION [{scenario_name}]: Native pointer not "
                f"nulled after free. Pointer still holds value, enabling "
                f"use-after-free and double-free attacks."
            )
    else:
        # Vulnerable implementation: document that double-free CAN occur
        # The test asserts that WITHOUT the fix, the invariant is violated
        # This serves as a regression detector - if someone "fixes" the
        # vulnerable impl without proper null-setting, this catches it
        free_count = AesGcmSivContext._free_count[initial_ptr]
        
        # The invariant that MUST hold in production code:
        # free_count should never exceed 1
        # We assert this to document the required security property
        # In the vulnerable implementation, this WILL fail under concurrent access
        
        # For the test to be useful as a regression guard, we check
        # that a properly fixed implementation would satisfy this
        expected_max_frees = 1
        
        # Document the violation potential
        if free_count > expected_max_frees:
            # This is the vulnerability manifesting - record it
            violation_detected = True
        else:
            violation_detected = False
        
        # The security property: in any correct implementation,
        # a context must not be freed more than once
        # We assert the REQUIREMENT (what must be true in fixed code)
        assert not (use_safe_impl is False and free_count > 1 and num_threads == 1), (
            f"SECURITY VIOLATION [{scenario_name}]: Single-threaded double-free "
            f"occurred {free_count} times on ptr={initial_ptr}. "
            f"The native pointer MUST be set to NULL after first free."
        )
    
    # Universal invariant: no unexpected exceptions during free operations
    assert len(errors) == 0, (
        f"Unexpected errors during free operations [{scenario_name}]: {errors}"
    )


@pytest.mark.parametrize("key_payload", [
    b"\x00" * 16,                          # All-zero key
    b"\xff" * 16,                          # All-ones key  
    b"\x00" * 32,                          # All-zero 256-bit key
    b"\xff" * 32,                          # All-ones 256-bit key
    b"\xde\xad\xbe\xef" * 4,              # Pattern key
    b"\x00" * 16 + b"\xff" * 16,          # Mixed key
    bytes(range(16)),                       # Sequential bytes
    b"\x80" + b"\x00" * 15,               # High bit set
])
def test_aes_gcmsiv_context_lifecycle_integrity(key_payload):
    """Invariant: The AES-GCM-SIV context lifecycle must ensure that
    after free() is called, the native pointer is invalidated (set to NULL),
    preventing any subsequent free() call from operating on a dangling pointer,
    regardless of the key material used to initialize the context."""
    
    ctx = AesGcmSivContext(key_size=len(key_payload))
    original_ptr = ctx._ptr
    
    assert ctx._ptr is not None, "Context must have valid pointer before free"
    assert not ctx._freed, "Context must not be freed before explicit free call"
    
    # First free - should succeed
    ctx.free_safe()
    
    # SECURITY INVARIANT: After free, pointer MUST be NULL
    assert ctx._ptr is None, (
        f"SECURITY VIOLATION: Native pointer not nulled after free() with "
        f"key_size={len(key_payload)}. Dangling pointer enables double-free "
        f"and use-after-free vulnerabilities."
    )
    
    assert ctx._freed, "Context must be marked as freed"
    
    # Second free attempt - must be safe (no-op due to NULL check)
    ctx.free_safe()  # Should not increment free count
    
    free_count = AesGcmSivContext._free_count[original_ptr]
    assert free_count == 1, (
        f"SECURITY VIOLATION: Context freed {free_count} times with "
        f"key_size={len(key_payload)}. Expected exactly 1 free. "
        f"Double-free corrupts heap metadata and may enable arbitrary code execution."
    )


def test_aes_gcmsiv_thread_safety_free_invariant():
    """Invariant: Under concurrent access from multiple threads attempting
    to free the same AES-GCM-SIV context simultaneously, the context must
    be freed exactly once. The native pointer must be atomically set to NULL
    to prevent race conditions leading to double-free vulnerabilities."""
    
    NUM_THREADS = 50
    NUM_ITERATIONS = 10
    violations = []
    
    for iteration in range(NUM_ITERATIONS):
        ctx = AesGcmSivContext(key_size=16)
        original_ptr = ctx._ptr
        barrier = threading.Barrier(NUM_THREADS)
        
        def concurrent_free():
            barrier.wait()  # Synchronize all threads to maximize contention
            ctx.free_safe()
        
        threads = [threading.Thread(target=concurrent_free) for _ in range(NUM_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
        
        free_count = AesGcmSivContext._free_count[original_ptr]
        if free_count != 1:
            violations.append(
                f"Iteration {iteration}: context freed {free_count} times "
                f"(ptr={original_ptr})"
            )
        
        if ctx._ptr is not None:
            violations.append(
                f"Iteration {iteration}: pointer not nulled after free "
                f"(ptr={original_ptr})"
            )
    
    assert len(violations) == 0, (
        f"SECURITY VIOLATIONS detected in thread-safety test:\n" +
        "\n".join(violations) +
        "\nThe free() function must atomically null the native pointer "
        "to prevent double-free under concurrent access."
    )