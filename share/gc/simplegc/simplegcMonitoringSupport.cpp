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
#include "gc/simplegc/simplegcMonitoringSupport.hpp"
#include "gc/simplegc/simplegcHeap.hpp"
#include "gc/shared/generationCounters.hpp"
#include "memory/allocation.hpp"
#include "memory/allocation.inline.hpp"
#include "memory/metaspaceCounters.hpp"
#include "memory/resourceArea.hpp"
#include "services/memoryService.hpp"
 
SimpleGCMonitoringSupport::SimpleGCMonitoringSupport(SimpleGCHeap* heap) {
  // _heap_counters  = new GenerationCounters(heap);
}

void SimpleGCMonitoringSupport::update_counters() {
  // MemoryService::track_memory_usage();

  // if (UsePerfData) {
  //   SimpleGCHeap* heap = SimpleGCHeap::heap();
  //   size_t used = heap->used();
  //   size_t capacity = heap->capacity();
  //   _heap_counters->update_all();
  //   MetaspaceCounters::update_performance_counters();
  //   CompressedClassSpaceCounters::update_performance_counters();
  // }
}

