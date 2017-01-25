
%module dps
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
 * Functions that must not be exposed
 */
%ignore DPS_DestroyPublication;
%ignore DPS_DestroySubscription;
%ignore DPS_SetSubscriptionData;
%ignore DPS_GetSubscriptionData;
%ignore DPS_SetPublicationData;
%ignore DPS_GetPublicationData;
%ignore DPS_GetLoop;

/*
 * Module is called dps we don't need the DPS prefix on every function
 */
%rename("%(strip:[DPS_])s") "";

/*
 * Mapping for types from stdint.h
 */
%typemap(in) uint8_t* = char*;
%typemap(in) int16_t = int;
%typemap(out) uint32_t = unsigned long;

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
                $1[i] = (char*)malloc(str->Utf8Length());
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
            fn->Call(SWIGV8_CURRENT_CONTEXT(), SWIGV8_CURRENT_CONTEXT()->Global(),
                     argc, argv);
        } else {
            Handler* handler = (Handler*)DPS_GetPublicationData(cb->pub);
            v8::Local<v8::Function> fn = v8::Local<v8::Function>::New(v8::Isolate::GetCurrent(), handler->fn);
            int argc = 2;
            v8::Local<v8::Value> argv[argc];
            argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(cb->pub), SWIGTYPE_p__DPS_Publication, 0);
            argv[1] = SWIGV8_STRING_NEW2((const char*)cb->payload, cb->len); /* For now just allow strings as payloads */
            fn->Call(SWIGV8_CURRENT_CONTEXT(), SWIGV8_CURRENT_CONTEXT()->Global(),
                     argc, argv);
        }
        delete cb;
        queue.pop();
    }
}

DPS_Status DestroyPublication(DPS_Publication* pub)
{
    Handler* handler = (Handler*)DPS_GetPublicationData(pub);
    delete handler;
    return DPS_DestroyPublication(pub);
}

DPS_Status DestroySubscription(DPS_Subscription* sub)
{
    Handler* handler = (Handler*)DPS_GetSubscriptionData(sub);
    delete handler;
    return DPS_DestroySubscription(sub);
}
%}

DPS_Status DestroyPublication(DPS_Publication* pub);
DPS_Status DestroySubscription(DPS_Subscription* sub);

/*
 * Publication acknowledgment function calls into JavaScript
 */
%{
static void AckHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    Callback* cb = (Callback*)calloc(1, sizeof(Callback));
    cb->pub = pub;
    cb->payload = payload;
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
    cb->pub = pub;
    cb->payload = payload;
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
