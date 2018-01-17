%module(docstring="Distributed Publish Subscribe for IoT") dps
%feature("autodoc", "1");

%{
extern "C" {
#include <dps/dps.h>
#include <dps/dbg.h>
#include <dps/err.h>
};
#include <mutex>
#include <queue>
%}

%include "cdata.i"
%include "constraints.i"
%include "typemaps.i"

/*
 * This warning is not relevant
 */
%warnfilter(451) _DPS_KeyCert;

/*
 * Functions that must not be exposed
 */
%ignore DPS_SubscriptionGetTopic;
%ignore DPS_SubscriptionGetNumTopics;
%ignore DPS_PublicationGetTopic;
%ignore DPS_PublicationGetNumTopics;
%ignore DPS_DestroyPublication;
%ignore DPS_DestroySubscription;
%ignore DPS_SetSubscriptionData;
%ignore DPS_GetSubscriptionData;
%ignore DPS_SetPublicationData;
%ignore DPS_GetPublicationData;
%ignore DPS_GetLoop;
%ignore DPS_DestroyNode;

/*
 * Declarations that are not relevant in JavaScript
 */
%ignore DPS_TRUE;
%ignore DPS_FALSE;

/*
 * Module is called dps we don't need the DPS prefix on every function
 */
%rename("debug") DPS_Debug;
%rename("%(regex:/DPS_(.*)/\\l\\1/)s", %$isfunction) "";
%rename("%(strip:[DPS_])s", %$not %$isfunction) "";

/*
 * Mapping for types from stdint.h
 */
%typemap(in) uint8_t* = char*;
%typemap(in) int16_t = int;
%typemap(out) int16_t = int;
%typemap(in) uint16_t = unsigned int;
%typemap(out) uint16_t = unsigned int;
%typemap(in) uint32_t = unsigned long;
%typemap(out) uint32_t = unsigned long;

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
            SWIG_exception_fail(SWIG_ArgError(ecode), "argument of type '" "int""'");
        }
    }

    $1 = b;
}

/*
 * This allows topic strings to be expressed as a list of strings
 */
%typemap(in) (const char** topics, size_t numTopics) {
    /* Expecting a list of strings */
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
                SWIG_exception_fail(SWIG_TypeError, "argument " "2"" of type '" "char *const *""'");
            }
        }
        $1[i] = NULL;
        $2 = arr->Length();
    } else {
        SWIG_exception_fail(SWIG_TypeError, "argument " "2"" of type '" "char *const *""'");
    }
}

/*
 * Post function call cleanup for topic strings
 */
%typemap(freearg) (const char** topics, size_t numTopics) {
    /* Freeing a list of strings */
    for (uint32_t i = 0; i < $2; ++i)
        free($1[i]);
    free($1);
}

%typemap(in,numinputs=0,noblock=1) size_t* n  {
  size_t sz;
  $1 = &sz;
}

%typemap(out) const char** subscriptionGetTopics %{
    $result = v8::Array::New(v8::Isolate::GetCurrent(), sz);
    for (size_t i = 0; i < sz; ++i) {
        v8::Local<v8::Array>::Cast($result)->Set(i, SWIG_FromCharPtr($1[i]));
    }
    free($1);
%}

%inline %{
const char** subscriptionGetTopics(const DPS_Subscription* sub, size_t* n)
{
    *n = DPS_SubscriptionGetNumTopics(sub);
    const char** topics = (const char**)calloc(*n, sizeof(const char *));
    for (size_t i = 0; i < *n; ++i) {
        topics[i] = DPS_SubscriptionGetTopic(sub, i);
    }
    return topics;
}
%}

%typemap(out) const char** publicationGetTopics %{
    $result = v8::Array::New(v8::Isolate::GetCurrent(), sz);
    for (size_t i = 0; i < sz; ++i) {
        v8::Local<v8::Array>::Cast($result)->Set(i, SWIG_FromCharPtr($1[i]));
    }
    free($1);
%}

%inline %{
const char** publicationGetTopics(const DPS_Publication* pub, size_t* n)
{
    *n = DPS_PublicationGetNumTopics(pub);
    const char** topics = (const char**)calloc(*n, sizeof(const char *));
    for (size_t i = 0; i < *n; ++i) {
        topics[i] = DPS_PublicationGetTopic(pub, i);
    }
    return topics;
}
%}

/*
 * For now just allow strings as payloads.
 * Eventually need to figure out how to handle binary data.
 */
%{
static uint8_t* AllocPayload(v8::Local<v8::Value> valRef, size_t* len)
{
    uint8_t* payload = NULL;
    if (valRef->IsString()) {
        v8::Local<v8::String> str = v8::Local<v8::String>::Cast(valRef);
        uint32_t sz = str->Utf8Length();
        payload = (uint8_t*)malloc(sz + 1);
        str->WriteUtf8((char*)payload);
        *len = (size_t)sz;
    }
    return payload;
}
%}

%typemap(in) (const uint8_t* pubPayload, size_t len) {
    $1 = AllocPayload($input, &$2);
    if (!$1) {
        SWIG_exception_fail(SWIG_TypeError, "not a string");
    }
}

%typemap(in) (const uint8_t* ackPayload, size_t len) {
    $1 = AllocPayload($input, &$2);
    if (!$1) {
        SWIG_exception_fail(SWIG_TypeError, "not a string");
    }
}

%typemap(freearg) (const uint8_t* pubPayload, size_t len) {
    free($1);
}

%typemap(freearg) (const uint8_t* ackPayload, size_t len) {
    free($1);
}

/*
 * Type maps for default arguments
 * These appear to not be implemented in JavaScript
 */

/*
 * Callback support
 */
%{
struct Handler {
    v8::Persistent<v8::Function> fn;
};
struct Callback {
    DPS_Subscription* sub;
    const DPS_Publication* pub;
    uint8_t* payload;
    size_t len;
};
static std::mutex mutex;
static std::queue<Callback*> queue;
static uv_async_t async;
static void async_cb(uv_async_t* handle)
{
    SWIGV8_HANDLESCOPE();

    std::unique_lock<std::mutex> lock(mutex);
    while (!queue.empty()) {
        Callback* cb = queue.front();
        if (cb->sub) {
            Handler* handler = (Handler*)DPS_GetSubscriptionData(cb->sub);
            v8::Local<v8::Function> fn = v8::Local<v8::Function>::New(v8::Isolate::GetCurrent(), handler->fn);
            int argc = 3;
            v8::Local<v8::Value> argv[argc];
            argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(cb->sub), SWIGTYPE_p__DPS_Subscription, 0);
            argv[1] = SWIG_NewPointerObj(SWIG_as_voidptr(cb->pub), SWIGTYPE_p__DPS_Publication, 0);
            argv[2] = SWIGV8_STRING_NEW2((const char*)cb->payload, cb->len); /* For now just allow strings as payloads */
            (void)fn->Call(SWIGV8_CURRENT_CONTEXT(), SWIGV8_CURRENT_CONTEXT()->Global(),
                     argc, argv);
            DPS_DestroyPublication((DPS_Publication*)cb->pub);
        } else {
            Handler* handler = (Handler*)DPS_GetPublicationData(cb->pub);
            v8::Local<v8::Function> fn = v8::Local<v8::Function>::New(v8::Isolate::GetCurrent(), handler->fn);
            int argc = 2;
            v8::Local<v8::Value> argv[argc];
            argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(cb->pub), SWIGTYPE_p__DPS_Publication, 0);
            argv[1] = SWIGV8_STRING_NEW2((const char*)cb->payload, cb->len); /* For now just allow strings as payloads */
            (void)fn->Call(SWIGV8_CURRENT_CONTEXT(), SWIGV8_CURRENT_CONTEXT()->Global(),
                     argc, argv);
        }
        if (cb->payload) {
            free(cb->payload);
        }
        free(cb);
        queue.pop();
    }
}

DPS_Status destroyPublication(DPS_Publication* pub)
{
    Handler* handler = (Handler*)DPS_GetPublicationData(pub);
    delete handler;
    return DPS_DestroyPublication(pub);
}

DPS_Status destroySubscription(DPS_Subscription* sub)
{
    Handler* handler = (Handler*)DPS_GetSubscriptionData(sub);
    delete handler;
    return DPS_DestroySubscription(sub);
}

DPS_Status destroyNode(DPS_Node* node)
{
    return DPS_DestroyNode(node, NULL, NULL);
}
%}

DPS_Status destroyPublication(DPS_Publication* pub);
DPS_Status destroySubscription(DPS_Subscription* sub);
DPS_Status destroyNode(DPS_Node* node);

/*
 * Publication acknowledgment function calls into JavaScript
 */
%{
static void AckHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    Callback* cb = (Callback*)calloc(1, sizeof(Callback));
    cb->pub = pub;
    cb->payload = (uint8_t*)malloc(len+1);
    memset(cb->payload, 0, len+1);
    memcpy(cb->payload, payload, len);
    cb->len = len;
    std::unique_lock<std::mutex> lock(mutex);
    queue.push(cb);
    uv_async_send(&async);
}
%}

/*
 * Acknowledgement callback wrapper
 */
%typemap(in) DPS_AcknowledgementHandler {
    if (!$input->IsFunction()) {
        SWIG_exception_fail(SWIG_TypeError, "argument of type '" "DPS_AcknowledgmentHandler""'");
    }
    if (arg1) {
        v8::Local<v8::Function> fn = v8::Local<v8::Function>::Cast($input);
        Handler* handler = new Handler();
        handler->fn.Reset(v8::Isolate::GetCurrent(), fn);
        DPS_Status ret = DPS_SetPublicationData(arg1, handler);
        if (ret != DPS_OK) {
            SWIG_exception_fail(SWIG_ERROR, "unable to set callback");
        }
        $1 = AckHandler;
    }
}

/*
 * Publication received function calls into JavaScript
 */
%{
static void PubHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    Callback* cb = (Callback*)calloc(1, sizeof(Callback));
    cb->sub = sub;
    cb->pub = (const DPS_Publication*)DPS_CopyPublication(pub);
    cb->payload = (uint8_t*)malloc(len+1);
    memset(cb->payload, 0, len+1);
    memcpy(cb->payload, payload, len);
    cb->len = len;
    std::unique_lock<std::mutex> lock(mutex);
    queue.push(cb);
    uv_async_send(&async);
}
%}

/*
 * Publication callback wrapper
 */
%typemap(in) DPS_PublicationHandler {
    if (!$input->IsFunction()) {
        SWIG_exception_fail(SWIG_TypeError, "argument of type '" "DPS_PublicationHandler""'");
    }
    if (arg1) {
        v8::Local<v8::Function> fn = v8::Local<v8::Function>::Cast($input);
        Handler* handler = new Handler();
        handler->fn.Reset(v8::Isolate::GetCurrent(), fn);
        DPS_Status ret = DPS_SetSubscriptionData(arg1, handler);
        if (ret != DPS_OK) {
            SWIG_exception_fail(SWIG_ERROR, "unable to set callback");
        }
        $1 = PubHandler;
    }
}

%{
static v8::Handle<v8::Value> UUIDToString(DPS_UUID* uuid)
{
    v8::Handle<v8::Value> val;
    const char* uuidStr = DPS_UUIDToString(uuid);
    if (uuidStr) {
        val = SWIGV8_STRING_NEW2(uuidStr, strnlen(uuidStr, 2 * sizeof(DPS_UUID)));
    }
    return val;
}
%}

%typemap(out) DPS_UUID* {
    $result = UUIDToString($1);
}

%typemap(in) DPS_UUID* {
    DPS_UUID* uuid = NULL;

    v8::Handle<v8::Value> obj($input);

    if (obj->IsUint8Array()) {
        v8::Local<v8::Uint8Array> arr = v8::Local<v8::Uint8Array>::Cast($input);
        uuid = (DPS_UUID*)calloc(1, sizeof(DPS_UUID));
        if (!uuid) {
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        v8::Local<v8::ArrayBuffer> buf = arr->Buffer();
        uint8_t* data = (uint8_t*)buf->GetContents().Data();
        if (arr->ByteLength() <= 16) {
            memcpy(uuid->val, data, arr->ByteLength());
        } else {
            memcpy(uuid->val, data, 16);
        }
    } else if (obj->IsArray()) {
        v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast($input);
        uint32_t n = arr->Length();
        uuid = (DPS_UUID*)calloc(1, sizeof(DPS_UUID));
        if (!uuid) {
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        uint32_t i;
        for (i = 0; (i < n) && (i < 16); ++i) {
            v8::Local<v8::Value> valRef;
            if (arr->Get(SWIGV8_CURRENT_CONTEXT(), i).ToLocal(&valRef)) {
                uuid->val[i] = valRef->Uint32Value();
            } else {
                free(uuid);
                SWIG_exception_fail(SWIG_TypeError, "argument of type '" "DPS_UUID""'");
            }
        }
    } else if (!obj->IsNull()) {
        SWIG_exception_fail(SWIG_TypeError, "argument of type '" "DPS_UUID""'");
    }
    $1 = uuid;
}

%typemap(freearg) DPS_UUID* {
    free($1);
}

/*
 * Used in DPS_SetContentKey.
 */
%typemap(in) (const DPS_Key* key) {
    DPS_Key* k = NULL;

    v8::Handle<v8::Value> obj($input);

    if (obj->IsUint8Array()) {
        uint8_t* data;
        v8::Local<v8::ArrayBuffer> buf;
        v8::Local<v8::Uint8Array> arr = v8::Local<v8::Uint8Array>::Cast($input);

        k = (DPS_Key*)calloc(1, sizeof(DPS_Key));
        if (!k) {
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        k->symmetric.len = arr->ByteLength();
        k->symmetric.key = (uint8_t*)calloc(k->symmetric.len, sizeof(uint8_t));
        if (!k->symmetric.key) {
            free(k);
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }

        buf = arr->Buffer();
        data = (uint8_t*)buf->GetContents().Data();
        memcpy((uint8_t*)k->symmetric.key, data, k->symmetric.len);
    } else if (obj->IsArray()) {
        v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast($input);
        k = (DPS_Key*)calloc(1, sizeof(DPS_Key));
        if (!k) {
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        k->symmetric.len = arr->Length();
        k->symmetric.key = (uint8_t*)calloc(k->symmetric.len, sizeof(uint8_t));
        if (!k->symmetric.key) {
            free(k);
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        size_t i;
        for (i = 0; i < k->symmetric.len; ++i) {
            v8::Local<v8::Value> valRef;
            if (arr->Get(SWIGV8_CURRENT_CONTEXT(), i).ToLocal(&valRef)) {
                ((uint8_t*)k->symmetric.key)[i] = valRef->Uint32Value();
            } else {
                free((uint8_t*)k->symmetric.key);
                free(k);
                SWIG_exception_fail(SWIG_TypeError, "argument of type '" "DPS_UUID""'");
            }
        }
    } else if (!obj->IsNull()) {
        SWIG_exception_fail(SWIG_TypeError, "argument of type '" "uint8_t *""'");
    }

    $1 = k;
}

%typemap(freearg) (const DPS_Key* key) {
    if ($1) {
        if ($1->symmetric.key) {
            free((uint8_t*)$1->symmetric.key);
        }
        free($1);
    }
}

%typemap(in) (const DPS_KeyId* keyId) {
    DPS_KeyId* kid = NULL;

    v8::Handle<v8::Value> obj($input);

    if (obj->IsUint8Array()) {
        uint8_t* data;
        v8::Local<v8::ArrayBuffer> buf;
        v8::Local<v8::Uint8Array> arr = v8::Local<v8::Uint8Array>::Cast($input);
        kid = (DPS_KeyId*)calloc(1, sizeof(DPS_KeyId));
        if (!kid) {
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        kid->len = arr->ByteLength();
        kid->id = (uint8_t*)calloc(kid->len, sizeof(uint8_t));
        if (!kid->id) {
            free(kid);
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }

        buf = arr->Buffer();
        data = (uint8_t*)buf->GetContents().Data();
        memcpy((uint8_t*)kid->id, data, kid->len);
    } else if (obj->IsArray()) {
        v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast($input);
        kid = (DPS_KeyId*)calloc(1, sizeof(DPS_KeyId));
        if (!kid) {
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        kid->len = arr->Length();
        kid->id = (uint8_t*)calloc(kid->len, sizeof(uint8_t));
        if (!kid->id) {
            free(kid);
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        size_t i;
        for (i = 0; i < kid->len; ++i) {
            v8::Local<v8::Value> valRef;
            if (arr->Get(SWIGV8_CURRENT_CONTEXT(), i).ToLocal(&valRef)) {
                ((uint8_t*)kid->id)[i] = valRef->Uint32Value();
            } else {
                free((uint8_t*)kid->id);
                free(kid);
                SWIG_exception_fail(SWIG_TypeError, "argument of type '" "uint8_t*""'");
            }
        }
    } else if (obj->IsString()) {
        v8::Local<v8::String> str = v8::Local<v8::String>::Cast(obj);
        kid = (DPS_KeyId*)calloc(1, sizeof(DPS_KeyId));
        if (!kid) {
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        kid->len = str->Utf8Length();
        kid->id = (uint8_t*)malloc(kid->len + 1);
        if (!kid->id) {
            free(kid);
            SWIG_exception_fail(SWIG_ERROR, "no memory");
        }
        str->WriteUtf8((char*)kid->id);
    } else if (!obj->IsNull()) {
        SWIG_exception_fail(SWIG_TypeError, "argument of type '" "DPS_KeyId *""'");
    }

    $1 = kid;
}

%typemap(freearg) (const DPS_KeyId* keyId) {
    if ($1) {
        if ($1->id) {
            free((uint8_t*)$1->id);
        }
        free($1);
    }
}

%typemap(in) (const char* key) {
    int res;
    char *buf = NULL;
    int alloc = SWIG_NEWOBJ;

    if (!$input->IsNull()) {
        res = SWIG_AsCharPtrAndSize($input, &buf, NULL, &alloc);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "setCertificate" "', argument of type '" "char const *""'");
        }
    }

    $1 = buf;
}

%typemap(freearg) (const char* key) {
    if ($1) {
        free($1);
    }
}

%typemap(in) (const char* password) {
    int res;
    char *buf = NULL;
    int alloc = SWIG_NEWOBJ;

    if (!$input->IsNull()) {
        res = SWIG_AsCharPtrAndSize($input, &buf, NULL, &alloc);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '" "setCertificate" "', argument of type '" "char const *""'");
        }
    }

    $1 = buf;
}

%typemap(freearg) (const char* password) {
    if ($1) {
        free($1);
    }
}

/*
 * Disallow NULL for these pointer types
 * These appear to have no effect on the generated code
 */
%apply Pointer NONNULL { DPS_Node* };
%apply Pointer NONNULL { DPS_UUID* };
%apply Pointer NONNULL { DPS_Subscription* };
%apply Pointer NONNULL { DPS_Publication* };
%apply Pointer NONNULL { DPS_PublicationAck* };
%apply Pointer NONNULL { DPS_NodeAddress* };

%include <dps/dps.h>
%include <dps/dbg.h>
%include <dps/err.h>

/*
 * Module initialization
 */
%init %{
    /* Must be called during module initialization to enable DPS callbacks */
    uv_async_init(uv_default_loop(), &async, async_cb);
    DPS_Debug = 0;
%}
