/**
 * @file
 * Access to a node's uv loop
 */

/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

#ifndef _DPS_LOOP_H
#define _DPS_LOOP_H

#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup node
 * @{
 */

/**
 * Get the uv event loop for this node. The only thing that is safe to do with the node
 * is to create an async callback. Other libuv APIs can then be called from within the
 * async callback.
 *
 * @param node     The local node to use
 *
 * @return The uv event loop
 */
uv_loop_t* DPS_GetLoop(DPS_Node* node);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
