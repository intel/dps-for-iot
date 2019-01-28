/**
 * @file
 * Network layer macros and functions
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

#include <assert.h>
#include <stdio.h>
#include <zephyr.h>
#include <entropy.h>

#include "mbedtls/entropy.h"
#include <dps/err.h>
#include <dps/dbg.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

int mbedtls_hardware_poll(void* data, unsigned char* output, size_t len, size_t* olen)
{
    struct device *dev = device_get_binding(CONFIG_ENTROPY_NAME);
    int ret;

	if (!dev) {
		DPS_ERRPRINT("Could not get entropy device\n");
		return 1;
	}
    ret = entropy_get_entropy(dev, output, len);
    if (ret) {
		DPS_ERRPRINT("Could not get entropy\n");
        return 1;
    }
    *olen = len;
    return 0;
}
