/*
 *******************************************************************
 *
 * Copyright 2018 Intel Corporation All rights reserved.
 *
 *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
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

#ifdef INCLUDE_DOC
%include "dps_doc.i"
#endif

/*
 * Module is called dps we don't need the DPS prefix on every function.
 * Note: can't combine strip and undercase, so regex instead.
 */
%rename("debug") DPS_Debug;
%rename("set_ca") DPS_SetCA;
%rename("set_trusted_ca") DPS_SetTrustedCA;
%rename("cbor_2_json") CBOR2JSON;
%rename("json_2_cbor") JSON2CBOR;

%rename("%(regex:/^_?DPS_(.*)$/\\1/)s") "";
%rename("%(regex:/^_?DPS_([A-Z][a-z0-9]+|UUID)$/\\L\\1/)s", %$isfunction) "";
%rename("%(regex:/^_?DPS_([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)$/\\L\\1_\\L\\2/)s", %$isfunction) "";
%rename("%(regex:/^_?DPS_([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)$/\\L\\1_\\L\\2_\\L\\3/)s",%$isfunction) "";
%rename("%(regex:/^_?DPS_([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)$/\\L\\1_\\L\\2_\\L\\3_\\L\\4/)s", %$isfunction) "";
/* Exclude UUID from this last regex to workaround SWIG issue */
%rename("%(regex:/^_?DPS_([A-Z][a-z0-9]+)([A-Z][a-z0-9]+)([A-Z][a-z0-9]+)([A-Z][a-z0-9]+)([A-Z][a-z0-9]+)$/\\L\\1_\\L\\2_\\L\\3_\\L\\4_\\L\\5/)s", %$isfunction) "";

%rename("%(regex:/^([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)$/\\L\\1_\\L\\2/)s", %$isfunction) "";
%rename("%(regex:/^([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)$/\\L\\1_\\L\\2_\\L\\3/)s",%$isfunction) "";


%{
typedef PyObject* Handle;

class Handler {
public:
    Handler(PyObject* obj) : m_obj(obj) { Py_INCREF(m_obj); }
    ~Handler() { Py_XDECREF(m_obj); }
    PyObject* m_obj;
};
%}

%extend _DPS_NodeAddress {
    const char* __str__() {
        return NodeAddrToString($self);
    }
}

%typemap(in) const sockaddr* (struct sockaddr_storage saddr) {
    PyObject* tuple[4];
    Py_ssize_t sz = SWIG_Python_UnpackTuple($input, "$symname", 2, 4, tuple);
    switch (sz) {
    case 0:
        SWIG_fail;
        break;
    case 3: {
        /*
         * A pair (host, port) is used for the AF_INET address family,
         * where host is a string representing an IPv4 address like
         * '100.50.200.5', and port is an integer.
         */
        struct sockaddr_in* in = (struct sockaddr_in*)&saddr;
        char* addr = NULL;
        int alloc = 0;
        int port;
        int res;
        /*
         * Family
         */
        in->sin_family = AF_INET;
        /*
         * Address
         */
        res = SWIG_AsCharPtrAndSize(tuple[0], &addr, NULL, &alloc);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        if (uv_inet_pton(AF_INET, addr, &in->sin_addr) != 0) {
            SWIG_exception_fail(SWIG_ArgError(SWIG_ValueError), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        if (alloc == SWIG_NEWOBJ) delete[] addr;
        /*
         * Port
         */
        res = SWIG_AsVal_int(tuple[1], &port);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        in->sin_port = htons(port);
        break;
    }
    case 5: {
        /*
         * For AF_INET6 address family, a four-tuple (host, port,
         * flowinfo, scopeid) is used, where flowinfo and scopeid
         * represents sin6_flowinfo and sin6_scope_id member in struct
         * sockaddr_in6 in C. For socket module methods, flowinfo and
         * scopeid can be omitted just for backward
         * compatibility. Note, however, omission of scopeid can cause
         * problems in manipulating scoped IPv6 addresses.
         */
        struct sockaddr_in6* in = (struct sockaddr_in6*)&saddr;
        char* addr = NULL;
        int alloc = 0;
        int port;
        unsigned long flowinfo;
        unsigned long scope_id;
        int res;
        /*
         * Family
         */
        in->sin6_family = AF_INET6;
        /*
         * Address
         */
        res = SWIG_AsCharPtrAndSize(tuple[0], &addr, NULL, &alloc);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        if (uv_inet_pton(AF_INET6, addr, &in->sin6_addr) != 0) {
            SWIG_exception_fail(SWIG_ArgError(SWIG_ValueError), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        if (alloc == SWIG_NEWOBJ) delete[] addr;
        /*
         * Port
         */
        res = SWIG_AsVal_int(tuple[1], &port);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        in->sin6_port = htons(port);
        /*
         * Flow info
         */
        res = SWIG_AsVal_unsigned_SS_long(tuple[2], &flowinfo);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        in->sin6_flowinfo = flowinfo;
        /*
         * Scope ID
         */
        res = SWIG_AsVal_unsigned_SS_long(tuple[3], &scope_id);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        in->sin6_scope_id = scope_id;
        break;
    }
    default:
        SWIG_exception_fail(SWIG_ArgError(SWIG_ValueError), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        break;
    }
    $1 = (struct sockaddr*)&saddr;
}

%typemap(default) (const char** topics, size_t numTopics) {
    $1 = NULL;
    $2 = 0;
}
%typemap(in) (const char** topics, size_t numTopics) {
    Py_ssize_t sz;
    Py_ssize_t i;
    int res;
    if (!PySequence_Check($input)) {
        SWIG_exception_fail(SWIG_ArgError(SWIG_TypeError), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
    }
    sz = PySequence_Length($input);
    if (sz) {
        $1 = (char**)calloc(sz, sizeof(char*));
        for (i = 0; i < sz; ++i) {
            int alloc = SWIG_NEWOBJ;
            PyObject *obj = PySequence_GetItem($input, i);
            res = SWIG_AsCharPtrAndSize(obj, &$1[i], NULL, &alloc);
            if (!SWIG_IsOK(res)) {
                SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
            }
        }
        $2 = sz;
    }
}
%typemap(freearg) (const char** topics, size_t numTopics) {
    size_t i;
    if ($1) {
        for (i = 0; i < $2; ++i) {
            delete[] $1[i];
        }
        free($1);
    }
}

%extend _DPS_UUID {
    const char* __str__() {
        return UUIDToString($self);
    }
}
