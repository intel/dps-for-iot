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
static int AsVal_bytes(Handle obj, uint8_t** bytes, size_t* len)
{
    int alloc = SWIG_NEWOBJ;
    if (SWIG_IsOK(SWIG_AsCharPtrAndSize(obj, (char**)bytes, len, &alloc))) {
        if (*len) {
            --(*len);
        }
        return SWIG_OK;
    } else if (PySequence_Check(obj)) {
        Py_ssize_t sz = PySequence_Length(obj);
        Py_ssize_t i;
        if (sz) {
            *bytes = new uint8_t[sz];
            for (i = 0; i < sz; ++i) {
                long v;
                PyObject *o = PySequence_GetItem(obj, i);
                int res = SWIG_AsVal_long(o, &v);
                if (!SWIG_IsOK(res)) {
                    return res;
                } else if ((v < 0) || (UINT8_MAX < v)) {
                    return SWIG_OverflowError;
                } else {
                    (*bytes)[i] = (uint8_t)v;
                }
            }
            *len = sz;
        }
        return SWIG_OK;
    } else {
        return SWIG_TypeError;
    }
}

static Handle From_bytes(const uint8_t* bytes, size_t len)
{
    return PyByteArray_FromStringAndSize((const char*)bytes, len);
}

static Handle From_topics(const char** topics, size_t len)
{
    PyObject* list = PyList_New(len);
    for (size_t i = 0; i < len; ++i) {
        PyList_SetItem(list, i, PyUnicode_FromString(topics[i]));
    }
    return list;
}

static DPS_Status KeyAndIdHandler(DPS_KeyStoreRequest* request)
{
    KeyStore* keyStore = (KeyStore*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(request));
    PyObject* requestObj;
    PyObject* ret;
    DPS_Status status = DPS_ERR_MISSING;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();
    requestObj = SWIG_NewPointerObj(SWIG_as_voidptr(request), SWIGTYPE_p__DPS_KeyStoreRequest, 0);
    ret = PyObject_CallFunction(keyStore->m_keyAndIdHandler->m_obj, (char*)"O", requestObj);
    if (ret) {
        SWIG_AsVal_int(ret, &status);
    }
    Py_XDECREF(ret);
    Py_XDECREF(requestObj);
    PyGILState_Release(gilState);

    return status;
}

static DPS_Status KeyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId)
{
    KeyStore* keyStore = (KeyStore*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(request));
    PyObject* requestObj;
    PyObject* keyIdObj;
    PyObject* ret;
    DPS_Status status = DPS_ERR_MISSING;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();
    requestObj = SWIG_NewPointerObj(SWIG_as_voidptr(request), SWIGTYPE_p__DPS_KeyStoreRequest, 0);
    if (keyId) {
        keyIdObj = From_bytes(keyId->id, keyId->len);
    } else {
        keyIdObj = From_bytes(NULL, 0);
    }
    ret = PyObject_CallFunction(keyStore->m_keyHandler->m_obj, (char*)"OO", requestObj, keyIdObj);
    if (ret) {
        SWIG_AsVal_int(ret, &status);
    }
    Py_XDECREF(ret);
    Py_XDECREF(keyIdObj);
    Py_XDECREF(requestObj);
    PyGILState_Release(gilState);

    return status;
}

static DPS_Status EphemeralKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key)
{
    KeyStore* keyStore = (KeyStore*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(request));
    PyObject* requestObj;
    PyObject* keyObj;
    PyObject* ret;
    DPS_Status status = DPS_ERR_MISSING;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();

    requestObj = SWIG_NewPointerObj(SWIG_as_voidptr(request), SWIGTYPE_p__DPS_KeyStoreRequest, 0);
    switch (key->type) {
    case DPS_KEY_SYMMETRIC:
        keyObj = SWIG_NewPointerObj(SWIG_as_voidptr(&key->symmetric), SWIGTYPE_p__DPS_KeySymmetric, 0);
        break;
    case DPS_KEY_EC:
        keyObj = SWIG_NewPointerObj(SWIG_as_voidptr(&key->ec), SWIGTYPE_p__DPS_KeyEC, 0);
        break;
    case DPS_KEY_EC_CERT:
        keyObj = SWIG_NewPointerObj(SWIG_as_voidptr(&key->cert), SWIGTYPE_p__DPS_KeyCert, 0);
        break;
    default:
        goto Exit;
    }
    ret = PyObject_CallFunction(keyStore->m_ephemeralKeyHandler->m_obj, (char*)"OO", requestObj, keyObj);
    if (ret) {
        SWIG_AsVal_int(ret, &status);
    }
    Py_XDECREF(ret);
    Py_XDECREF(keyObj);
    Py_XDECREF(requestObj);

 Exit:
    PyGILState_Release(gilState);
    return status;
}

static DPS_Status CAHandler(DPS_KeyStoreRequest* request)
{
    KeyStore* keyStore = (KeyStore*)DPS_GetKeyStoreData(DPS_KeyStoreHandle(request));
    PyObject* requestObj;
    PyObject* ret;
    DPS_Status status = DPS_ERR_MISSING;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();
    requestObj = SWIG_NewPointerObj(SWIG_as_voidptr(request), SWIGTYPE_p__DPS_KeyStoreRequest, 0);
    ret = PyObject_CallFunction(keyStore->m_caHandler->m_obj, (char*)"O", requestObj);
    if (ret) {
        SWIG_AsVal_int(ret, &status);
    }
    Py_XDECREF(ret);
    Py_XDECREF(requestObj);
    PyGILState_Release(gilState);

    return status;
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    Handler* handler = (Handler*)data;
    PyObject* nodeObj;
    PyObject* ret;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();
    nodeObj = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p__DPS_Node, 0);
    ret = PyObject_CallFunction(handler->m_obj, (char*)"O", nodeObj);
    Py_XDECREF(ret);
    Py_XDECREF(nodeObj);
    PyGILState_Release(gilState);

    delete handler;
}

static void OnLinkComplete(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data)
{
    Handler* handler = (Handler*)data;
    PyObject* nodeObj;
    PyObject* addrObj;
    PyObject* ret;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();
    nodeObj = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p__DPS_Node, 0);
    addrObj = SWIG_NewPointerObj(SWIG_as_voidptr(addr), SWIGTYPE_p__DPS_NodeAddress, 0);
    ret = PyObject_CallFunction(handler->m_obj, (char*)"OOi", nodeObj, addrObj, status);
    Py_XDECREF(ret);
    Py_XDECREF(addrObj);
    Py_XDECREF(nodeObj);
    PyGILState_Release(gilState);

    delete handler;
}

static void OnNodeAddressComplete(DPS_Node* node, DPS_NodeAddress* addr, void* data)
{
    Handler* handler = (Handler*)data;
    PyObject* nodeObj;
    PyObject* addrObj;
    PyObject* ret;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();
    nodeObj = SWIG_NewPointerObj(SWIG_as_voidptr(node), SWIGTYPE_p__DPS_Node, 0);
    addrObj = SWIG_NewPointerObj(SWIG_as_voidptr(addr), SWIGTYPE_p__DPS_NodeAddress, 0);
    ret = PyObject_CallFunction(handler->m_obj, (char*)"OO", nodeObj, addrObj);
    Py_XDECREF(ret);
    Py_XDECREF(addrObj);
    Py_XDECREF(nodeObj);
    PyGILState_Release(gilState);

    delete handler;
}

static void AcknowledgementHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    PublicationData* data = (PublicationData*)DPS_GetPublicationData(pub);
    PyObject* pubObj;
    PyObject* payloadObj;
    PyObject* ret;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();
    pubObj = SWIG_NewPointerObj(SWIG_as_voidptr(pub), SWIGTYPE_p__DPS_Publication, 0);
    payloadObj = From_bytes(payload, len);
    ret = PyObject_CallFunction(data->m_acknowledgementHandler->m_obj, (char*)"OO", pubObj, payloadObj);
    Py_XDECREF(ret);
    Py_XDECREF(payloadObj);
    Py_XDECREF(pubObj);
    PyGILState_Release(gilState);
}

static void OnPublishComplete(DPS_Publication* pub, DPS_Status status)
{
    PublicationData* data = (PublicationData*)DPS_GetPublicationData(pub);
    PyObject* pubObj;
    PyObject* ret;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();
    pubObj = SWIG_NewPointerObj(SWIG_as_voidptr(pub), SWIGTYPE_p__DPS_Publication, 0);
    ret = PyObject_CallFunction(data->m_onPublishComplete->m_obj, (char*)"Oi", pubObj, status);
    Py_XDECREF(ret);
    Py_XDECREF(pubObj);
    PyGILState_Release(gilState);
}

static void PublicationHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    Handler* handler = (Handler*)DPS_GetSubscriptionData(sub);
    PyObject* subObj;
    PyObject* pubObj;
    PyObject* payloadObj;
    PyObject* ret;
    PyGILState_STATE gilState;

    gilState = PyGILState_Ensure();
    subObj = SWIG_NewPointerObj(SWIG_as_voidptr(sub), SWIGTYPE_p__DPS_Subscription, 0);
    pubObj = SWIG_NewPointerObj(SWIG_as_voidptr(pub), SWIGTYPE_p__DPS_Publication, 0);
    payloadObj = From_bytes(payload, len);
    ret = PyObject_CallFunction(handler->m_obj, (char*)"OOO", subObj, pubObj, payloadObj);
    Py_XDECREF(ret);
    Py_XDECREF(payloadObj);
    Py_XDECREF(pubObj);
    Py_XDECREF(subObj);
    PyGILState_Release(gilState);
}

static void InitializeModule()
{
    PyEval_InitThreads();
    DPS_Debug = 0;
}
%}
