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

/*
 * Module is called dps we don't need the DPS prefix on every function
 */
%rename("ackPublicationBufs") AckPublicationBufs;
%rename("debug") DPS_Debug;
%rename("uuidToString") DPS_UUIDToString;
%rename("uuidCompare") DPS_UUIDCompare;
%rename("cbor2JSON") CBOR2JSON;
%rename("json2CBOR") JSON2CBOR;
%rename("createNode") CreateNode;
%rename("destroyKeyStore") DestroyKeyStore;
%rename("destroyPublication") DestroyPublication;
%rename("destroySubscription") DestroySubscription;
%rename("publicationGetTopics") PublicationGetTopics;
%rename("publishBufs") PublishBufs;
%rename("setCertificate") SetCertificate;
%rename("subscriptionGetTopics") SubscriptionGetTopics;
%rename("%(regex:/^_?DPS_(.*)/\\l\\1/)s", %$isfunction) "";
%rename("%(regex:/^_?DPS_(.*)/\\1/)s", %$not %$isfunction) "";

%{
typedef v8::Handle<v8::Value> Handle;

class Handler {
public:
    Handler() { }
    Handler(v8::Handle<v8::Value> val) { Set(val); }
    void Set(v8::Handle<v8::Value> val) { m_val.Reset(v8::Isolate::GetCurrent(), val); }
    v8::Persistent<v8::Value> m_val;
};
%}

/*
 * Allow JavaScript true, false for DPS boolean (int)
 */
%typemap(in) int {
    int b = 0;

    if ($input->IsBoolean()) {
        b = $input->BooleanValue() ? 1 : 0;
    } else {
        int ecode = SWIG_AsVal_int($input, &b);
        if (!SWIG_IsOK(ecode)) {
            SWIG_exception_fail(SWIG_ArgError(ecode), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
    }

    $1 = b;
}

%extend _DPS_NodeAddress {
    const char* inspect(int depth, void* opts) {
        return NodeAddrToString($self, depth, opts);
    }
    const char* toString() {
        return NodeAddrToString($self, 0, NULL);
    }
}

%typemap(in) const sockaddr* (struct sockaddr_storage saddr) {
    char* family = NULL;
    int alloc = 0;
    int res;
    if(!$input->IsObject()) {
        SWIG_exception_fail(SWIG_TypeError, "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
    }
    v8::Handle<v8::Object> obj = $input->ToObject();
    v8::Local<v8::Value> addressVal;
    v8::Local<v8::Value> familyVal;
    v8::Local<v8::Value> portVal;
    v8::Local<v8::Value> flowinfoVal;
    v8::Local<v8::Value> scopeidVal;
    if (obj->Get(SWIGV8_CURRENT_CONTEXT(), SWIGV8_STRING_NEW("address")).ToLocal(&addressVal) &&
        !addressVal->IsString()) {
        SWIG_exception_fail(SWIG_TypeError, "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
    }
    if (!obj->Get(SWIGV8_CURRENT_CONTEXT(), SWIGV8_STRING_NEW("family")).ToLocal(&familyVal) ||
        !familyVal->IsString()) {
        SWIG_exception_fail(SWIG_TypeError, "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
    }
    if (!obj->Get(SWIGV8_CURRENT_CONTEXT(), SWIGV8_STRING_NEW("port")).ToLocal(&portVal) ||
        !portVal->IsNumber()) {
        SWIG_exception_fail(SWIG_TypeError, "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
    }
    obj->Get(SWIGV8_CURRENT_CONTEXT(), SWIGV8_STRING_NEW("flowinfo")).ToLocal(&flowinfoVal);
    obj->Get(SWIGV8_CURRENT_CONTEXT(), SWIGV8_STRING_NEW("scopeid")).ToLocal(&scopeidVal);
    res = SWIG_AsCharPtrAndSize(familyVal, &family, NULL, &alloc);
    if (!SWIG_IsOK(res)) {
        SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
    }
    if (!strcmp(family, "IPv4")) {
        struct sockaddr_in* in = (struct sockaddr_in*)&saddr;
        char* addr = NULL;
        int alloc = 0;
        int port;
        /*
         * Family
         */
        in->sin_family = AF_INET;
        /*
         * Address
         */
        if (addressVal->IsString()) {
            res = SWIG_AsCharPtrAndSize(addressVal, &addr, NULL, &alloc);
            if (!SWIG_IsOK(res)) {
                SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
            }
            if (uv_inet_pton(AF_INET, addr, &in->sin_addr) != 0) {
                SWIG_exception_fail(SWIG_ArgError(SWIG_ValueError), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
            }
            if (alloc == SWIG_NEWOBJ) delete[] addr;
        } else {
            in->sin_addr.s_addr = INADDR_ANY;
        }
        /*
         * Port
         */
        res = SWIG_AsVal_int(portVal, &port);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        in->sin_port = htons(port);
    } else if (!strcmp(family, "IPv6")) {
        struct sockaddr_in6* in = (struct sockaddr_in6*)&saddr;
        char* addr = NULL;
        int alloc = 0;
        int port;
        unsigned long flowinfo = 0;
        unsigned long scope_id = 0;
        /*
         * Family
         */
        in->sin6_family = AF_INET6;
        /*
         * Address
         */
        if (addressVal->IsString()) {
            res = SWIG_AsCharPtrAndSize(addressVal, &addr, NULL, &alloc);
            if (!SWIG_IsOK(res)) {
                SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
            }
            if (uv_inet_pton(AF_INET6, addr, &in->sin6_addr) != 0) {
                SWIG_exception_fail(SWIG_ArgError(SWIG_ValueError), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
            }
            if (alloc == SWIG_NEWOBJ) delete[] addr;
        } else {
            memcpy(&in->sin6_addr, &in6addr_any, sizeof(in->sin6_addr));
        }
        /*
         * Port
         */
        res = SWIG_AsVal_int(portVal, &port);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
        in->sin6_port = htons(port);
        /*
         * Flow info
         */
        if (flowinfoVal->IsNumber()) {
            res = SWIG_AsVal_unsigned_SS_long(flowinfoVal, &flowinfo);
            if (!SWIG_IsOK(res)) {
                SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
            }
        }
        in->sin6_flowinfo = flowinfo;
        /*
         * Scope ID
         */
        if (scopeidVal->IsNumber()) {
            res = SWIG_AsVal_unsigned_SS_long(scopeidVal, &scope_id);
            if (!SWIG_IsOK(res)) {
                SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
            }
        }
        in->sin6_scope_id = scope_id;
    } else {
        SWIG_exception_fail(SWIG_ArgError(SWIG_ValueError), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
    }
    if (alloc == SWIG_NEWOBJ) delete[] family;
    $1 = (struct sockaddr*)&saddr;
}

%typemap(default) (const char** topics, size_t numTopics) {
    $1 = NULL;
    $2 = 0;
}
%typemap(in) (const char** topics, size_t numTopics) {
    if ($input->IsArray()) {
        v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast($input);
        uint32_t n = arr->Length();
        $1 = (char**)calloc(n + 1, sizeof(char*));
        uint32_t i;
        for (i = 0; i < n; ++i) {
            v8::Local<v8::Value> valRef;
            if (arr->Get(SWIGV8_CURRENT_CONTEXT(), i).ToLocal(&valRef)) {
                v8::Local<v8::String> str = v8::Local<v8::String>::Cast(valRef);
                $1[i] = (char*)malloc(str->Utf8Length() + 1);
                str->WriteUtf8($1[i]);
            } else {
                for (uint32_t j = 0; j < i; ++j)
                    free($1[j]);
                free($1);
                SWIG_exception_fail(SWIG_TypeError, "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
            }
        }
        $1[i] = NULL;
        $2 = arr->Length();
    } else {
        SWIG_exception_fail(SWIG_TypeError, "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
    }
}
%typemap(freearg) (const char** topics, size_t numTopics) {
    for (uint32_t i = 0; i < $2; ++i)
        free($1[i]);
    free($1);
}

%typemap(in) (Buffer* bufs, size_t numBufs) {
    /*
     * typemap(default) doesn't appear to be initializing the values
     * in the JavaScript binding
     */
    $1 = NULL;
    $2 = 0;

    size_t len;
    size_t i;
    if ($input->IsArray()) {
        v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast($input);
        len = arr->Length();
        if (len) {
            $1 = new Buffer[len];
            $2 = len;
            for (i = 0; i < len; ++i) {
                v8::Local<v8::Value> valRef;
                if (!arr->Get(SWIGV8_CURRENT_CONTEXT(), i).ToLocal(&valRef)) {
                    SWIG_exception_fail(SWIG_ArgError(SWIG_TypeError), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
                }
                int res = $1[i].Set(valRef);
                if (!SWIG_IsOK(res)) {
                    SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
                }
            }
        }
    } else {
        $1 = new Buffer[1];
        $2 = 1;
        int res = $1[0].Set($input);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
        }
    }
}

%extend _DPS_UUID {
    const char* inspect(int depth, void* opts) {
        return UUIDToString($self, depth, opts);
    }
    const char* toString() {
        return UUIDToString($self, 0, NULL);
    }
}
