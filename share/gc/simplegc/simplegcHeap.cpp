/*
 * Copyright (c) 2017, 2018, Red Hat, Inc. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#include "precompiled.hpp"
#include "gc/simplegc/simplegcHeap.hpp"
#include "gc/simplegc/simplegcMemoryPool.hpp"
#include "gc/shared/gcArguments.hpp"
#include "gc/shared/locationPrinter.inline.hpp"
#include "memory/allocation.hpp"
#include "memory/allocation.inline.hpp"
#include "memory/resourceArea.hpp"
#include "memory/universe.hpp"
#include "runtime/atomic.hpp"
#include "runtime/globals.hpp"
#include "gc/shared/gcTraceTime.inline.hpp"
#include "runtime/vmThread.hpp"
#include "code/codeCache.hpp"
#include "runtime/biasedLocking.hpp"
#include "gc/shared/strongRootsScope.hpp"
#include "memory/iterator.hpp"
#include "memory/universe.hpp"
#include "prims/jvmtiExport.hpp"
#include "gc/shared/weakProcessor.hpp"
#include "runtime/synchronizer.hpp"
#include "classfile/systemDictionary.hpp"
#include "classfile/classLoaderDataGraph.hpp"
#include "classfile/stringTable.hpp"
#include "logging/log.hpp"
#include "utilities/stack.inline.hpp"
#include "services/management.hpp"
#include "gc/shared/preservedMarks.hpp"
#include "gc/shared/preservedMarks.inline.hpp"
#include "oops/oop.inline.hpp"
#include "gc/shared/markBitMap.inline.hpp"
#include "runtime/mutexLocker.hpp"

void SimpleGCHeap::allocate_marking_bitmap(Pair<char *, size_t> heap_base_and_size_pair){

};

void SimpleGCHeap::do_roots(OopClosure *cl, bool everything)
{

  log_info(gc)("Begin process roots.");
  StrongRootsScope scope(1);
  log_info(gc)("StrongRootsScope process roots.");

  //Closures
  CLDToOopClosure clds(cl, ClassLoaderData::_claim_none);
  log_info(gc)("CLDToOopClosure process roots.");
  MarkingCodeBlobClosure blobs(cl, CodeBlobToOopClosure::FixRelocations);
  log_info(gc)("MarkingCodeBlobClosure process roots.");
  //Lock for codecache
  {
    MutexLocker lock(CodeCache_lock, Mutex::_no_safepoint_check_flag);
    // log_info(gc)("CodeCache_lock process roots.");

    CodeCache::blobs_do(&blobs);
    // log_info(gc)("CodeCache::blobs_do process roots.");
  }

  ClassLoaderDataGraph::cld_do(&clds);
  log_info(gc)("ClassLoaderDataGraph process roots.");
  Universe::oops_do(cl);
  Management::oops_do(cl);
  JvmtiExport::oops_do(cl);
  log_info(gc)("JvmtiExport process roots.");
  JNIHandles::oops_do(cl);
  WeakProcessor::oops_do(cl);
  ObjectSynchronizer::oops_do(cl);
  SystemDictionary::oops_do(cl);
  Threads::possibly_parallel_oops_do(false, cl, &blobs);

  if (everything)
  {
    StringTable::shared_oops_do(cl);
  }
  log_info(gc)("Process roots.");
}

jint SimpleGCHeap::initialize()
{
  size_t align = HeapAlignment;
  size_t init_byte_size = align_up(InitialHeapSize, align);
  size_t max_byte_size = align_up(MaxHeapSize, align);

  // Initialize backing storage
  ReservedHeapSpace heap_rs = Universe::reserve_heap(max_byte_size, align);
  _virtual_space.initialize(heap_rs, init_byte_size);

  MemRegion committed_region((HeapWord *)_virtual_space.low(), (HeapWord *)_virtual_space.high());
  MemRegion reserved_region((HeapWord *)_virtual_space.low_boundary(), (HeapWord *)_virtual_space.high_boundary());

  initialize_reserved_region(heap_rs);

  // Pair<char*, size_t> heap_base_address_and_size = Pair<char*, size_t>(heap_rs.base(), heap_rs.size())

  _space = new ContiguousSpace();
  _space->initialize(committed_region, /* clear_space = */ true, /* mangle_space = */ true);

  // Precompute hot fields
  // _max_tlab_size = MIN2(CollectedHeap::max_tlab_size(), align_object_size(SimpleGCMaxTLABSize / HeapWordSize));
  _max_tlab_size = MIN2(CollectedHeap::max_tlab_size(), align_object_size(4 * M / HeapWordSize));

  size_t SimpleUpdateCounterStep = 1 * M;
  _step_counter_update = MIN2<size_t>(max_byte_size / 16, SimpleUpdateCounterStep);
  size_t simpleGCPrintHeapSteps = 20;
  _step_heap_print = max_byte_size / simpleGCPrintHeapSteps;
  size_t SimpleGCTLABDecayTime = 1000;
  _decay_time_ns = (int64_t)(SimpleGCTLABDecayTime)*NANOSECS_PER_MILLISEC;

  // Enable monitoring
  _monitoring_support = new SimpleGCMonitoringSupport(this);
  _last_counter_update = 0;
  _last_heap_print = 0;

  // Install barrier set
  BarrierSet::set_barrier_set(new SimpleGCBarrierSet());

  size_t _bitmap_page_size = UseLargePages ? (size_t)os::large_page_size() : os::vm_page_size();
  size_t _bitmap_size = MarkBitMap::compute_size(heap_rs.size());
  _bitmap_size = align_up(_bitmap_size, _bitmap_page_size);

  //TODO
  //alocate marking bitmap
  {
    ReservedSpace bitmap(_bitmap_size, _bitmap_page_size);
    // TODO MemTracker
    _bitmap_region = MemRegion((HeapWord *)bitmap.base(), bitmap.size() / HeapWordSize);
    MemRegion heap_region = MemRegion((HeapWord *)heap_rs.base(), heap_rs.size() / HeapWordSize);
    _bitmap.initialize(heap_region, _bitmap_region);
    // _bitmap_region = MemRegion();
  }

  //TODO
  //alocate marking bitmap

  // All done, print out the configuration
  // if (init_byte_size != max_byte_size) {
  //   log_info(gc)("Resizeable heap; starting at " SIZE_FORMAT "M, max: " SIZE_FORMAT "M, step: " SIZE_FORMAT "M",
  //                init_byte_size / M, max_byte_size / M, SimpleGCMinHeapExpand / M);
  // } else {
  //   log_info(gc)("Non-resizeable heap; start/max: " SIZE_FORMAT "M", init_byte_size / M);
  // }
  //ADD TODO Delete
  log_info(gc)("HeapWordSize: %d WordSize", HeapWordSize);
  log_info(gc)("Non-resizeable heap; start/max: " SIZE_FORMAT "M", max_byte_size / M);
  log_info(gc)("Using TLAB allocation; max: " SIZE_FORMAT "K", _max_tlab_size * HeapWordSize / K);
  // if (UseTLAB) {
  //   log_info(gc)("Using TLAB allocation; max: " SIZE_FORMAT "K", _max_tlab_size * HeapWordSize / K);
  //   if (SimpleGCElasticTLAB) {
  //     log_info(gc)("Elastic TLABs enabled; elasticity: %.2fx", SimpleGCTLABElasticity);
  //   }
  //   if (SimpleGCElasticTLABDecay) {
  //     log_info(gc)("Elastic TLABs decay enabled; decay time: " SIZE_FORMAT "ms", SimpleGCTLABDecayTime);
  //   }
  // } else {
  //   log_info(gc)("Not using TLAB allocation");
  // }

  return JNI_OK;
}

void SimpleGCHeap::post_initialize()
{
  CollectedHeap::post_initialize();
}

void SimpleGCHeap::initialize_serviceability()
{
  _pool = new SimpleGCMemoryPool(this);
  _memory_manager.add_pool(_pool);
}

GrowableArray<GCMemoryManager *> SimpleGCHeap::memory_managers()
{
  GrowableArray<GCMemoryManager *> memory_managers(1);
  memory_managers.append(&_memory_manager);
  return memory_managers;
}

GrowableArray<MemoryPool *> SimpleGCHeap::memory_pools()
{
  GrowableArray<MemoryPool *> memory_pools(1);
  memory_pools.append(_pool);
  return memory_pools;
}

size_t SimpleGCHeap::unsafe_max_tlab_alloc(Thread *thr) const
{
  // Return max allocatable TLAB size, and let allocation path figure out
  // the actual allocation size. Note: result should be in bytes.
  return _max_tlab_size * HeapWordSize;
}

SimpleGCHeap *SimpleGCHeap::heap()
{
  CollectedHeap *heap = Universe::heap();
  assert(heap != NULL, "Uninitialized access to SimpleGCHeap::heap()");
  assert(heap->kind() == CollectedHeap::SimpleGC, "Not an SimpleGC heap");
  return (SimpleGCHeap *)heap;
}

//TODO
HeapWord *SimpleGCHeap::allocate_work(size_t size)
{
  assert(is_object_aligned(size), "Allocation size should be aligned: " SIZE_FORMAT, size);

  HeapWord *res = _space->par_allocate(size);

  size_t space_left = max_capacity() - capacity();
  if ((res == NULL) && (size > space_left))
  {
    log_info(gc)("Failed to allocate %d %s bytes", (int)byte_size_in_proper_unit(size), proper_unit_for_byte_size(size));
    return NULL;
  }
  log_info(gc)("Success allocate %d %s bytes", (int)byte_size_in_proper_unit(size), proper_unit_for_byte_size(size));

  // log_info(gc)("Object size: %d ", (int)size);
  // while (res == NULL) {
  //   // Allocation failed, attempt expansion, and retry:
  //   MutexLocker ml(Heap_lock);

  //   size_t space_left = max_capacity() - capacity();
  //   size_t want_space = MAX2(size, SimpleGCMinHeapExpand);

  //   if (want_space < space_left) {
  //     // Enough space to expand in bulk:
  //     bool expand = _virtual_space.expand_by(want_space);
  //     assert(expand, "Should be able to expand");
  //   } else if (size < space_left) {
  //     // No space to expand in bulk, and this allocation is still possible,
  //     // take all the remaining space:
  //     bool expand = _virtual_space.expand_by(space_left);
  //     assert(expand, "Should be able to expand");
  //   } else {
  //     // No space left:
  //     return NULL;
  //   }

  //   _space->set_end((HeapWord *) _virtual_space.high());
  //   res = _space->par_allocate(size);
  // }

  size_t used = _space->used();

  // Allocation successful, update counters
  {
    size_t last = _last_counter_update;
    if ((used - last >= _step_counter_update) && Atomic::cmpxchg(&_last_counter_update, last, used) == last)
    {
      _monitoring_support->update_counters();
    }
  }

  // ...and print the occupancy line, if needed
  {
    size_t last = _last_heap_print;
    if ((used - last >= _step_heap_print) && Atomic::cmpxchg(&_last_heap_print, last, used) == last)
    {
      print_heap_info(used);
      print_metaspace_info();
    }
  }

  assert(is_object_aligned(res), "Object should be aligned: " PTR_FORMAT, p2i(res));
  return res;
}

class VM_SimpleGCCollect : public VM_Operation
{
private:
  GCCause::Cause _cause;
  SimpleGCHeap *_heap;
  static size_t _last_used;

public:
  VM_SimpleGCCollect(GCCause::Cause cause) : _cause(cause), _heap(SimpleGCHeap::heap()){};
  const char *name() const { return "I`m the fucking gc."; };
  virtual VMOp_Type type() const { return VMOp_SimpleGCCollect; };

  virtual void doit();
  virtual bool doit_prologue();
  virtual void doit_epilogue();
};

void VM_SimpleGCCollect::doit()
{
  GCCauseSetter x(_heap, _cause);
  _heap->do_full_collection(false);
}

bool VM_SimpleGCCollect::doit_prologue()
{
  log_info(gc)("doit_prologue in SimpleGC");
  Heap_lock->lock();
  size_t used = _heap->used();
  size_t capacity = _heap->capacity();
  size_t new_allocated = used > _last_used ? used - _last_used : 0;
  //TODO
  // we can choose more complicated ways to decide whether to gc. Maybe?
  log_info(gc)("used: " SIZE_FORMAT " %s", byte_size_in_proper_unit(used), proper_unit_for_byte_size(used));
  log_info(gc)("capactity: " SIZE_FORMAT " %s", byte_size_in_proper_unit(capacity), proper_unit_for_byte_size(capacity));
  log_info(gc)("new_allocated: " SIZE_FORMAT " %s", byte_size_in_proper_unit(new_allocated), proper_unit_for_byte_size(new_allocated));
  if (_cause != GCCause::_allocation_failure || (new_allocated > capacity / 100 && used > capacity / 2))
  {
    return true;
  }
  else
  {
    Heap_lock->unlock();
    return false;
  }
}

size_t VM_SimpleGCCollect::_last_used = 0;

void VM_SimpleGCCollect::doit_epilogue()
{
  log_info(gc)("doit_epilogue in SimpleGC");
  _last_used = _heap->used();
  Heap_lock->unlock();
}

HeapWord *
SimpleGCHeap::allocate_new_tlab(size_t min_size,
                                size_t requested_size,
                                size_t *actual_size)
{
  Thread *thread = Thread::current();

  // Defaults in case elastic paths are not taken
  bool fits = true;
  size_t size = requested_size;
  size_t ergo_tlab = requested_size;
  int64_t time = 0;

  // if (SimpleGCElasticTLAB) {
  //   ergo_tlab = SimpleGCThreadLocalData::ergo_tlab_size(thread);

  //   if (SimpleGCElasticTLABDecay) {
  //     int64_t last_time = SimpleGCThreadLocalData::last_tlab_time(thread);
  //     time = (int64_t) os::javaTimeNanos();

  //     assert(last_time <= time, "time should be monotonic");

  //     // If the thread had not allocated recently, retract the ergonomic size.
  //     // This conserves memory when the thread had initial burst of allocations,
  //     // and then started allocating only sporadically.
  //     if (last_time != 0 && (time - last_time > _decay_time_ns)) {
  //       ergo_tlab = 0;
  //       SimpleGCThreadLocalData::set_ergo_tlab_size(thread, 0);
  //     }
  //   }

  //   // If we can fit the allocation under current TLAB size, do so.
  //   // Otherwise, we want to elastically increase the TLAB size.
  //   fits = (requested_size <= ergo_tlab);
  //   if (!fits) {
  //     size = (size_t) (ergo_tlab * SimpleGCTLABElasticity);
  //   }
  // }

  // Always honor boundaries
  // size = clamp(size, min_size, _max_tlab_size);
  size = MAX2(min_size, MIN2(_max_tlab_size, size));

  // Always honor alignment
  size = align_up(size, MinObjAlignment);

  // Check that adjustments did not break local and global invariants
  assert(is_object_aligned(size),
         "Size honors object alignment: " SIZE_FORMAT, size);
  assert(min_size <= size,
         "Size honors min size: " SIZE_FORMAT " <= " SIZE_FORMAT, min_size, size);
  assert(size <= _max_tlab_size,
         "Size honors max size: " SIZE_FORMAT " <= " SIZE_FORMAT, size, _max_tlab_size);
  assert(size <= CollectedHeap::max_tlab_size(),
         "Size honors global max size: " SIZE_FORMAT " <= " SIZE_FORMAT, size, CollectedHeap::max_tlab_size());

  if (log_is_enabled(Trace, gc))
  {
    ResourceMark rm;
    log_trace(gc)("TLAB size for \"%s\" (Requested: " SIZE_FORMAT "K, Min: " SIZE_FORMAT
                  "K, Max: " SIZE_FORMAT "K, Ergo: " SIZE_FORMAT "K) -> " SIZE_FORMAT "K",
                  thread->name(),
                  requested_size * HeapWordSize / K,
                  min_size * HeapWordSize / K,
                  _max_tlab_size * HeapWordSize / K,
                  ergo_tlab * HeapWordSize / K,
                  size * HeapWordSize / K);
  }

  // All prepared, let's do it!
  HeapWord *res = allocate_work(size);

  if (res != NULL)
  {
    // Allocation successful
    *actual_size = size;
    // if (SimpleGCElasticTLABDecay) {
    //   SimpleGCThreadLocalData::set_last_tlab_time(thread, time);
    // }
    // if (SimpleGCElasticTLAB && !fits) {
    //   // If we requested expansion, this is our new ergonomic TLAB size
    //   SimpleGCThreadLocalData::set_ergo_tlab_size(thread, size);
    // }
  }
  else
  {
    // Allocation failed, reset ergonomics to try and fit smaller TLABs
    // if (SimpleGCElasticTLAB) {
    //   SimpleGCThreadLocalData::set_ergo_tlab_size(thread, 0);
    // }
  }

  return res;
}

void SimpleGCHeap::vmentry_collect(GCCause::Cause cause)
{
  VM_SimpleGCCollect scOp = VM_SimpleGCCollect(cause);
  VMThread::execute(&scOp);
}

HeapWord *SimpleGCHeap::allocate_or_collect_work(size_t size)
{
  HeapWord *res = allocate_work(size);
  if (res == NULL)
  {
    GCCause::Cause cause = GCCause::_allocation_failure;
    vmentry_collect(cause);
    res = allocate_work(size);
  }
  return res;
}

HeapWord *SimpleGCHeap::mem_allocate(size_t size, bool *gc_overhead_limit_was_exceeded)
{
  *gc_overhead_limit_was_exceeded = false;
  return allocate_or_collect_work(size);
}

typedef Stack<oop, mtGC> SimpleGCMarkStack;

class SimpleGCMarkClosure : public BasicOopIterateClosure
{
private:
  SimpleGCMarkStack *const _stack;
  MarkBitMap *const _bitmap;

public:
  virtual void do_oop(oop *o) { do_oop_work(o); };
  virtual void do_oop(narrowOop *o) { do_oop_work(o); };
  SimpleGCMarkClosure(SimpleGCMarkStack *stack, MarkBitMap *bitmap) : _stack(stack), _bitmap(bitmap) {}

private:
  template <class T>
  void do_oop_work(T *p)
  {
    T o = RawAccess<>::oop_load(p);
    if (!CompressedOops::is_null(o))
    {
      oop obj = CompressedOops::decode_not_null(o);
      if (!_bitmap->is_marked(obj))
      {
        _bitmap->mark(obj);
        _stack->push(obj);
      }
    }
  };
};

void SimpleGCHeap::walk_bitmap(ObjectClosure *cl)
{
  HeapWord *limit = _space->top();
  HeapWord *addr = _bitmap.get_next_marked_addr(_space->bottom(), limit);
  while (addr < limit)
  {
    oop obj = oop(addr);
    cl->do_object(obj);
    addr += 1;
    if (addr < limit)
    {
      addr = _bitmap.get_next_marked_addr(addr, limit);
    }
  }
}

class SimpleGCCalculateNewLocationClosure : public ObjectClosure
{
private:
  HeapWord *_compact_point;
  PreservedMarks *const _preserved_marks;

public:
  SimpleGCCalculateNewLocationClosure(HeapWord *compact_start, PreservedMarks *preserved_marks)
      : _compact_point(compact_start), _preserved_marks(preserved_marks)
  {
  }
  void do_object(oop obj)
  {
    if (cast_from_oop<HeapWord *>(obj) != _compact_point)
    {
      markWord mark = obj->mark_raw();
      if (mark.must_be_preserved(obj->klass()))
      {
        _preserved_marks->push(obj, mark);
      }
      obj->forward_to(oop(_compact_point));
    }
    _compact_point += obj->size();
  }
  HeapWord *compact_point()
  {
    return _compact_point;
  }
};

void SimpleGCHeap::entry_collect(GCCause::Cause cause)
{
  log_info(gc)("SimpleGC entry collect.");
  //
  size_t stat_reachable_heap = 0;
  {
    GCTraceTime(Info, gc) time("Step 0: Prologue", NULL);

    if (!os::commit_memory((char *)_bitmap_region.start(), _bitmap_region.byte_size(), false))
    {
      log_warning(gc)("SimpleGC failed to commit native memory for marking bitmap, GC failed.");
      return;
    }
    ensure_parsability(true);

    //What this means?
    //TODO
    // CodeCache::gc_prelogue();
    BiasedLocking::preserve_marks();
    DerivedPointerTable::clear();
  }

  {
    log_info(gc)("Step 1 mark all live objects.");
    GCTraceTime(Info, gc) time("Step 1: Mark", NULL);
    //mark all live objects with closure.
    SimpleGCMarkStack stack;
    SimpleGCMarkClosure cl = SimpleGCMarkClosure(&stack, &_bitmap);

    process_roots(&cl);
    stat_reachable_heap = stack.size();
    log_info(gc)("stat_reachable_heap: stack.size() " SIZE_FORMAT "", byte_size_in_proper_unit(stat_reachable_heap));
    while (!stack.is_empty())
    {
      oop obj = stack.pop();
      obj->oop_iterate(&cl);
      stat_reachable_heap++;
    }

    //TODO
    //what this means?
    DerivedPointerTable::set_active(false);
  }

  {
    GCTraceTime(Info, gc) time("Step 2: Calculate new locations", NULL);
    //walk along all these oops in `_bitmap` and calculate the new locations.
  }

  {
    GCTraceTime(Info, gc) time("Step 3: Adjust pointers", NULL);
  }

  {
    GCTraceTime(Info, gc) time("Step 4: Actual move objects", NULL);
  }

  {
    GCTraceTime(Info, gc) time("Step 5: Epilogue", NULL);
  }

  //
}

void SimpleGCHeap::collect(GCCause::Cause cause)
{
  switch (cause)
  {
  case GCCause::_metadata_GC_threshold:
  case GCCause::_metadata_GC_clear_soft_refs:
    // Receiving these causes means the VM itself entered the safepoint for metadata collection.
    // While SimpleGC does not do GC, it has to perform sizing adjustments, otherwise we would
    // re-enter the safepoint again very soon.
    assert(SafepointSynchronize::is_at_safepoint(), "Expected at safepoint");
    log_info(gc)("GC request for \"%s\" is handled", GCCause::to_string(cause));
    MetaspaceGC::compute_new_size();
    print_metaspace_info();
    break;
  default:
  {
    log_info(gc)("GC request for \"%s\" is ignored", GCCause::to_string(cause));
    //TODO collect data.
    if (SafepointSynchronize::is_at_safepoint())
    {
      entry_collect(cause);
    }
    else
    {
      vmentry_collect(cause);
    }
  }
  }
  _monitoring_support->update_counters();
}
void SimpleGCHeap::do_full_collection(bool clear_all_soft_refs)
{
  collect(gc_cause());
}

void SimpleGCHeap::object_iterate(ObjectClosure *cl)
{
  _space->object_iterate(cl);
}

void SimpleGCHeap::print_on(outputStream *st) const
{
  st->print_cr("SimpleGC Heap");

  // Cast away constness:
  ((VirtualSpace)_virtual_space).print_on(st);

  st->print_cr("Allocation space:");
  _space->print_on(st);

  MetaspaceUtils::print_on(st);
}

bool SimpleGCHeap::print_location(outputStream *st, void *addr) const
{
  return BlockLocationPrinter<SimpleGCHeap>::print_location(st, addr);
}

void SimpleGCHeap::print_tracing_info() const
{
  print_heap_info(used());
  print_metaspace_info();
}

void SimpleGCHeap::print_heap_info(size_t used) const
{
  size_t reserved = max_capacity();
  size_t committed = capacity();

  if (reserved != 0)
  {
    log_info(gc)("Heap: " SIZE_FORMAT "%s reserved, " SIZE_FORMAT "%s (%.2f%%) committed, " SIZE_FORMAT "%s (%.2f%%) used",
                 byte_size_in_proper_unit(reserved), proper_unit_for_byte_size(reserved),
                 byte_size_in_proper_unit(committed), proper_unit_for_byte_size(committed),
                 committed * 100.0 / reserved,
                 byte_size_in_proper_unit(used), proper_unit_for_byte_size(used),
                 used * 100.0 / reserved);
  }
  else
  {
    log_info(gc)("Heap: no reliable data");
  }
}

void SimpleGCHeap::print_metaspace_info() const
{
  size_t reserved = MetaspaceUtils::reserved_bytes();
  size_t committed = MetaspaceUtils::committed_bytes();
  size_t used = MetaspaceUtils::used_bytes();

  if (reserved != 0)
  {
    log_info(gc, metaspace)("Metaspace: " SIZE_FORMAT "%s reserved, " SIZE_FORMAT "%s (%.2f%%) committed, " SIZE_FORMAT "%s (%.2f%%) used",
                            byte_size_in_proper_unit(reserved), proper_unit_for_byte_size(reserved),
                            byte_size_in_proper_unit(committed), proper_unit_for_byte_size(committed),
                            committed * 100.0 / reserved,
                            byte_size_in_proper_unit(used), proper_unit_for_byte_size(used),
                            used * 100.0 / reserved);
  }
  else
  {
    log_info(gc, metaspace)("Metaspace: no reliable data");
  }
}
