/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#pragma once

#include "P_CacheDir.h"
#include "EvacuationKey.h"

struct EvacuationBlock {
  union {
    unsigned int init;
    struct {
      unsigned int done          : 1; // has been evacuated
      unsigned int pinned        : 1; // check pinning timeout
      unsigned int evacuate_head : 1; // check pinning timeout
      unsigned int unused        : 29;
    } f;
  };

  int readers;
  Dir dir;
  Dir new_dir;
  // we need to have a list of evacuationkeys because of collision.
  EvacuationKey evac_frags;
  CacheEvacuateDocVC *earliest_evacuator;
  LINK(EvacuationBlock, link);
};
