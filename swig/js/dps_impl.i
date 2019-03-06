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

%{
#include <condition_variable>
#include <mutex>
#include <queue>

static int AsVal_bytes(Handle obj, uint8_t** bytes, size_t* len)
{
    (*len) = 0;
    (*bytes) = NULL;
    if (obj->IsUint8Array()) {
        v8::Local<v8::ArrayBuffer> buf;
        v8::Local<v8::Uint8Array> arr = v8::Local<v8::Uint8Array>::Cast(obj);
        (*len) = arr->ByteLength();
        (*bytes) = new uint8_t[*len];
        size_t off = arr->ByteOffset();
        uint8_t* data = (uint8_t*)arr->Buffer()->GetContents().Data();
        memcpy((*bytes), &data[off], (*len));
    } else if (obj->IsArray()) {
        v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast(obj);
        (*len) = arr->Length();
        (*bytes) = new uint8_t[*len];
        size_t i;
        for (i = 0; i < (*len); ++i) {
            v8::Local<v8::Value> valRef;
            if (arr->Get(SWIGV8_CURRENT_CONTEXT(), i).ToLocal(&valRef)) {
                (*bytes)[i] = valRef->Uint32Value();
            } else {
                delete[] (*bytes);
                return SWIG_TypeError;
            }
        }
    } else if (obj->IsString()) {
        v8::Local<v8::String> str = v8::Local<v8::String>::Cast(obj);
        (*len) = str->Utf8Length();
        (*bytes) = new uint8_t[*len + 1];
        str->WriteUtf8((char*)(*bytes));
    } else if (!obj->IsNull()) {
        return SWIG_TypeError;
    }
    return SWIG_NEWOBJ;
}

/*
 * AsVal_bytes always returns a mutable object
 */
static int AsSafeVal_bytes(Handle obj, uint8_t** bytes, size_t* len)
{
    return AsVal_bytes(obj, bytes, len);
}

static Handle From_bytes(const uint8_t* bytes, size_t len)
{
    v8::Handle<v8::Array> arr = SWIGV8_ARRAY_NEW();
    for (size_t i = 0; i < len; ++i) {
        arr->Set(i, SWIGV8_INTEGER_NEW_UNS(bytes[i]));
    }
    return arr;
}

static Handle From_topics(const char** topics, size_t len)
{
    v8::Handle<v8::Array> arr = v8::Array::New(v8::Isolate::GetCurrent(), len);
    for (size_t i = 0; i < len; ++i) {
        v8::Local<v8::Array>::Cast(arr)->Set(i, SWIG_FromCharPtr(topics[i]));
    }
    return arr;
}

class Callback {
public:
    std::condition_variable* m_cond;
    Callback() : m_cond(NULL) { }
    virtual ~Callback() { }
    virtual void Call() = 0;
};

static std::mutex mutex;
static std::queue<Callback*> queue;
static uv_thread_t node_thread;
static uv_async_t async;

static void async_cb(uv_async_t* handle)
{
    SWIGV8_HANDLESCOPE();

    mutex.lock();
    while (!queue.empty()) {
        Callback* cb = queue.front();
        std::condition_variable* cond = cb->m_cond;
        queue.pop();
        mutex.unlock();
        cb->Call();
        delete cb;
        if (cond) {
            cond->notify_one();
        }
        mutex.lock();
    }
    mutex.unlock();
}

static void sync_send(Callback* cb)
{
    uv_thread_t self = uv_thread_self();
    if (uv_thread_equal(&node_thread, &self)) {
        cb->Call();
        delete cb;
    } else {
        std::condition_variable cond;
        std::unique_lock<std::mutex> lock(mutex);
        cb->m_cond = &cond;
        queue.push(cb);
        uv_async_send(&async);
        cond.wait(lock);
    }
}

static int CallFunction(v8::Persistent<v8::Value>& valRef, int argc, v8::Local<v8::Value>* argv)
{
    int result = DPS_ERR_FAILURE;
    v8::Local<v8::Value> val = v8::Local<v8::Value>::New(v8::Isolate::GetCurrent(), valRef);
    if (val->IsFunction()) {
        v8::Local<v8::Function> fn = v8::Local<v8::Function>::Cast(val);
        v8::MaybeLocal<v8::Value> ret = fn->Call(SWIGV8_CURRENT_CONTEXT(), SWIGV8_CURRENT_CONTEXT()->Global(),
                                                 argc, argv);
        if (!ret.IsEmpty()) {
            result = ret.ToLocalChecked()->IntegerValue();
        }
    }
    return result;
}

class KeyAndIdCallback : public Callback {
public:
    DPS_KeyStoreRequest* m_request;
    DPS_Status* m_ret;
    KeyAndIdCallback(DPS_KeyStoreRequest* request, DPS_Status* ret)
         : m_request(request), m_ret(ret) { }
    void Call() {
        KeyStore* keyStore = (KeyStore*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(m_request));
        int argc = 1;
        v8::Local<v8::Value> argv[argc];
        argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(m_request), SWIGTYPE_p__DPS_KeyStoreRequest, 0);
        *m_ret = CallFunction(keyStore->m_keyAndIdHandler->m_val, argc, argv);
        if (*m_ret != DPS_OK) {
            *m_ret = DPS_ERR_MISSING;
        }
    }
};

static DPS_Status KeyAndIdHandler(DPS_KeyStoreRequest* request)
{
    DPS_Status ret;
    sync_send(new KeyAndIdCallback(request, &ret));
    return ret;
}

class KeyCallback : public Callback {
public:
    DPS_KeyStoreRequest* m_request;
    const DPS_KeyId* m_keyId;
    DPS_Status* m_ret;
    KeyCallback(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId, DPS_Status* ret)
        : m_request(request), m_keyId(keyId), m_ret(ret) { }
    void Call() {
        KeyStore* keyStore = (KeyStore*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(m_request));
        int argc = 2;
        v8::Local<v8::Value> argv[argc];
        argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(m_request), SWIGTYPE_p__DPS_KeyStoreRequest, 0);
        if (m_keyId) {
            argv[1] = From_bytes(m_keyId->id, m_keyId->len);
        } else {
            argv[1] = From_bytes(NULL, 0);
        }
        *m_ret = CallFunction(keyStore->m_keyHandler->m_val, argc, argv);
        if (*m_ret != DPS_OK) {
            *m_ret = DPS_ERR_MISSING;
        }
    }
};

static DPS_Status KeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId)
{
    DPS_Status ret;
    sync_send(new KeyCallback(request, keyId, &ret));
    return ret;
}

class EphemeralKeyCallback : public Callback {
public:
    DPS_KeyStoreRequest* m_request;
    const DPS_Key* m_key;
    DPS_Status* m_ret;
    EphemeralKeyCallback(DPS_KeyStoreRequest* request, const DPS_Key* key, DPS_Status* ret)
        : m_request(request), m_key(key), m_ret(ret) { }
    void Call() {
        KeyStore* keyStore = (KeyStore*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(m_request));
        int argc = 2;
        v8::Local<v8::Value> argv[argc];
        argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(m_request), SWIGTYPE_p__DPS_KeyStoreRequest, 0);
        switch (m_key->type) {
        case DPS_KEY_SYMMETRIC:
            argv[1] = SWIG_NewPointerObj(SWIG_as_voidptr(&m_key->symmetric), SWIGTYPE_p__DPS_KeySymmetric, 0);
            break;
        case DPS_KEY_EC:
            argv[1] = SWIG_NewPointerObj(SWIG_as_voidptr(&m_key->ec), SWIGTYPE_p__DPS_KeyEC, 0);
            break;
        case DPS_KEY_EC_CERT:
            argv[1] = SWIG_NewPointerObj(SWIG_as_voidptr(&m_key->cert), SWIGTYPE_p__DPS_KeyCert, 0);
            break;
        }
        *m_ret = CallFunction(keyStore->m_ephemeralKeyHandler->m_val, argc, argv);
        if (*m_ret != DPS_OK) {
            *m_ret = DPS_ERR_MISSING;
        }
    }
};

static DPS_Status EphemeralKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    DPS_Status ret;
    sync_send(new EphemeralKeyCallback(request, key, &ret));
    return ret;
}

class CACallback : public Callback {
public:
    DPS_KeyStoreRequest* m_request;
    DPS_Status* m_ret;
    CACallback(DPS_KeyStoreRequest* request, DPS_Status* ret)
         : m_request(request), m_ret(ret) { }
    void Call() {
        KeyStore* keyStore = (KeyStore*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(m_request));
        int argc = 1;
        v8::Local<v8::Value> argv[argc];
        argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(m_request), SWIGTYPE_p__DPS_KeyStoreRequest, 0);
        *m_ret = CallFunction(keyStore->m_caHandler->m_val, argc, argv);
        if (*m_ret != DPS_OK) {
            *m_ret = DPS_ERR_MISSING;
        }
    }
};

static DPS_Status CAHandler(DPS_KeyStoreRequest* request)
{
    DPS_Status ret;
    sync_send(new CACallback(request, &ret));
    return ret;
}

class NodeDestroyedCallback : public Callback {
public:
    const DPS_Node* m_node;
    Handler* m_handler;
    NodeDestroyedCallback(DPS_Node* node, void* data) : m_node(node), m_handler((Handler*)data) { }
    ~NodeDestroyedCallback() { delete m_handler; }
    void Call() {
        int argc = 1;
        v8::Local<v8::Value> argv[argc];
        argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(m_node), SWIGTYPE_p__DPS_Node, 0);
        CallFunction(m_handler->m_val, argc, argv);
    }
};

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    sync_send(new NodeDestroyedCallback(node, data));
}

class LinkCompleteCallback : public Callback {
public:
    const DPS_Node* m_node;
    DPS_NodeAddress* m_addr;
    DPS_Status m_status;
    Handler* m_handler;
    LinkCompleteCallback(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
        : m_node(node), m_addr(DPS_CreateAddress()), m_status(status), m_handler((Handler*)data) {
        DPS_CopyAddress(m_addr, addr);
    }
    ~LinkCompleteCallback() {
        delete m_handler;
        DPS_DestroyAddress(m_addr);
    }
    void Call() {
        int argc = 3;
        v8::Local<v8::Value> argv[argc];
        argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(m_node), SWIGTYPE_p__DPS_Node, 0);
        argv[1] = SWIG_NewPointerObj(SWIG_as_voidptr(m_addr), SWIGTYPE_p__DPS_NodeAddress, 0);
        argv[2] = SWIG_From_int(m_status);
        CallFunction(m_handler->m_val, argc, argv);
    }
};

static void OnLinkComplete(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    sync_send(new LinkCompleteCallback(node, addr, status, data));
}

class NodeAddressCompleteCallback : public Callback {
public:
    const DPS_Node* m_node;
    DPS_NodeAddress* m_addr;
    Handler* m_handler;
    NodeAddressCompleteCallback(DPS_Node* node, const DPS_NodeAddress* addr, void* data)
        : m_node(node), m_addr(DPS_CreateAddress()), m_handler((Handler*)data) {
        DPS_CopyAddress(m_addr, addr);
    }
    ~NodeAddressCompleteCallback() {
        delete m_handler;
        DPS_DestroyAddress(m_addr);
    }
    void Call() {
        int argc = 2;
        v8::Local<v8::Value> argv[argc];
        argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(m_node), SWIGTYPE_p__DPS_Node, 0);
        argv[1] = SWIG_NewPointerObj(SWIG_as_voidptr(m_addr), SWIGTYPE_p__DPS_NodeAddress, 0);
        CallFunction(m_handler->m_val, argc, argv);
    }
};

static void OnNodeAddressComplete(DPS_Node* node, const DPS_NodeAddress* addr, void* data)
{
    sync_send(new NodeAddressCompleteCallback(node, addr, data));
}

class AcknowledgementCallback : public Callback {
public:
    const DPS_Publication* m_pub;
    uint8_t* m_payload;
    size_t m_len;
    AcknowledgementCallback(DPS_Publication* pub, uint8_t* payload, size_t len) {
        m_pub = pub;
        m_payload = new uint8_t[len];
        memcpy(m_payload, payload, len);
        m_len = len;
    }
    virtual ~AcknowledgementCallback() {
        delete[] m_payload;
    }
    void Call() {
        Handler* handler = (Handler*)DPS_GetPublicationData(m_pub);
        int argc = 2;
        v8::Local<v8::Value> argv[argc];
        argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(m_pub), SWIGTYPE_p__DPS_Publication, 0);
        argv[1] = From_bytes(m_payload, m_len);
        CallFunction(handler->m_val, argc, argv);
    }
};

static void AcknowledgementHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    sync_send(new AcknowledgementCallback(pub, payload, len));
}

class PublicationCallback : public Callback {
public:
    DPS_Subscription* m_sub;
    DPS_Publication* m_pub;
    uint8_t* m_payload;
    size_t m_len;
    PublicationCallback(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len) {
        m_sub = sub;
        m_pub = DPS_CopyPublication(pub);
        m_payload = new uint8_t[len];
        memcpy(m_payload, payload, len);
        m_len = len;
    }
    virtual ~PublicationCallback() {
        DPS_DestroyPublication(m_pub);
        delete[] m_payload;
    }
    void Call() {
        Handler* handler = (Handler*)DPS_GetSubscriptionData(m_sub);
        int argc = 3;
        v8::Local<v8::Value> argv[argc];
        argv[0] = SWIG_NewPointerObj(SWIG_as_voidptr(m_sub), SWIGTYPE_p__DPS_Subscription, 0);
        argv[1] = SWIG_NewPointerObj(SWIG_as_voidptr(m_pub), SWIGTYPE_p__DPS_Publication, 0);
        argv[2] = From_bytes(m_payload, m_len);
        CallFunction(handler->m_val, argc, argv);
    }
};

static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    sync_send(new PublicationCallback(sub, pub, payload, len));
}

static void InitializeModule()
{
    node_thread = uv_thread_self();
    uv_async_init(uv_default_loop(), &async, async_cb);
    DPS_Debug = 0;
}
%}
