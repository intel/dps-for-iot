/*
 *******************************************************************
 *
 * Copyright 2017 Intel Corporation All rights reserved.
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

#ifndef _TEST_H
#define _TEST_H

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dps/targets.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/err.h>
#include <dps/private/dps.h>

#if DPS_TARGET == DPS_TARGET_WINDOWS
#define SLEEP(t) Sleep(t)
#elif DPS_TARGET == DPS_TARGET_LINUX
#include <unistd.h>
#define SLEEP(t) usleep((t) * 1000)
#elif DPS_TARGET == DPS_TARGET_ZEPHYR
#define SLEEP(t) k_sleep(t)
#endif

#define ASSERT(cond) do { assert(cond); if (!(cond)) exit(EXIT_FAILURE); } while (0)

static int atLine;
#define CHECK(cond)   if (!cond) { atLine = __LINE__; goto failed; }

#endif
