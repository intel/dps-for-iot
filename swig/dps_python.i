%module(docstring="Distributed Publish Subscribe for IoT") dps
%feature("autodoc", "1");

%{
#include <dps/dps.h>
#include <dps/dbg.h>
#include <dps/synchronous.h>
#include <safe_lib.h>
/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

%}

%include "cdata.i"
%include "constraints.i"
%include "typemaps.i"

/*
 * This warning is not relevant
 */
%warnfilter(451) _DPS_KeyCert;

/*
 * Functions that must not be exposed in Python
 */
%ignore DPS_SubscriptionGetTopic;
%ignore DPS_SubscriptionGetNumTopics;
%ignore DPS_PublicationGetTopic;
%ignore DPS_PublicationGetNumTopics;
%ignore DPS_SetSubscriptionData;
%ignore DPS_GetSubscriptionData;
%ignore DPS_SetPublicationData;
%ignore DPS_GetPublicationData;
%ignore DPS_GetLoop;

/*
 * Declarations that are not relevant in Python
 */
%ignore DPS_TRUE;
%ignore DPS_FALSE;

/*
 * Only exposing the synchronous versions of these
 */
%ignore DPS_Link;
%ignore DPS_Unlink;
%ignore DPS_ResolveAddress;

/*
 * Module is called dps we don't need the DPS prefix on every function.
 * Note: can't combine strip and undercase, so regex instead.
 */
%rename("debug") DPS_Debug;
%rename("set_ca") DPS_SetCA;
%rename("set_trusted_ca") DPS_SetTrustedCA;
%rename("%(regex:/DPS_([A-Z][a-z0-9]+|UUID)/\\L\\1/)s", %$isfunction) "";
%rename("%(regex:/DPS_([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)/\\L\\1_\\L\\2/)s", %$isfunction) "";
%rename("%(regex:/DPS_([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)/\\L\\1_\\L\\2_\\L\\3/)s", %$isfunction) "";
%rename("%(regex:/DPS_([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)([A-Z][a-z0-9]+|UUID)/\\L\\1_\\L\\2_\\L\\3_\\L\\4/)s", %$isfunction) "";
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
%typemap(in) DPS_UUID* = PyObject*;

/*
 * Debug control
 */
%inline %{
int DPS_Debug;
%}

/*
 * This allows topic strings to be expressed as a list of strings
 */
%typemap(in) (const char** topics, size_t numTopics) {
    /* Expecting a list of strings */
    if (PyList_Check($input)) {
        Py_ssize_t i;
        Py_ssize_t sz = PyList_Size($input);
        $1 = (char**)malloc((sz + 1) * sizeof(char*));
        for (i = 0; i < sz; ++i) {
            PyObject *ob = PyList_GetItem($input, i);
            if (PyString_Check(ob))
                $1[i] = PyString_AsString(ob);
            else {
                PyErr_SetString(PyExc_TypeError,"must be a list of one or more strings");
                SWIG_fail;
            }
        }
        $1[i] = 0;
        $2 = sz;
    } else {
        PyErr_SetString(PyExc_TypeError,"not a list");
        SWIG_fail;
    }
}

/*
 * Post function call cleanup for topic strings
 */
%typemap(freearg) (const char** topics, size_t numTopics) {
    free($1);
}

%typemap(in,numinputs=0,noblock=1) size_t* n  {
  size_t sz;
  $1 = &sz;
}

%typemap(out) const char** subscription_get_topics %{
    $result = PyList_New(sz);
    for (int i = 0; i < sz; ++i) {
        PyList_SetItem($result, i, PyUnicode_FromString($1[i]));
    }
    free($1);
%}

%inline %{
const char** subscription_get_topics(const DPS_Subscription* sub, size_t* n)
{
    *n = DPS_SubscriptionGetNumTopics(sub);
    const char** topics = calloc(*n, sizeof(const char *));
    for (size_t i = 0; i < *n; ++i) {
        topics[i] = DPS_SubscriptionGetTopic(sub, i);
    }
    return topics;
}
%}

%typemap(out) const char** publication_get_topics %{
    $result = PyList_New(sz);
    for (int i = 0; i < sz; ++i) {
        PyList_SetItem($result, i, PyUnicode_FromString($1[i]));
    }
    free($1);
%}

%inline %{
const char** publication_get_topics(const DPS_Publication* pub, size_t* n)
{
    *n = DPS_PublicationGetNumTopics(pub);
    const char** topics = calloc(*n, sizeof(const char *));
    for (size_t i = 0; i < *n; ++i) {
        topics[i] = DPS_PublicationGetTopic(pub, i);
    }
    return topics;
}
%}

%{
/*
 * For now just allow strings as payloads.
 * Eventually need to figure out how to handle binary data.
 */
static uint8_t* AllocPayload(PyObject* py, size_t* len)
{
    uint8_t* str = NULL;
    if (PyString_Check(py)) {
        Py_ssize_t sz = PyString_Size(py);
        str = malloc(sz + 1);
        memcpy_s(str, sz, PyString_AsString(py), sz);
        str[sz] = 0;
        *len = (size_t)sz;
    } else {
        PyErr_SetString(PyExc_TypeError,"not a string");
    }
    return str;
}
%}

%typemap(in) (const uint8_t* pubPayload, size_t len) {
    $1 = AllocPayload($input, &$2);
    if (!$1) {
        PyErr_SetString(PyExc_MemoryError,"Allocation of pub payload failed");
        SWIG_fail;
    }
}

%typemap(in) (const uint8_t* ackPayload, size_t len) {
    $1 = AllocPayload($input, &$2);
    if (!$1) {
        PyErr_SetString(PyExc_MemoryError,"Allocation of ack payload failed");
        SWIG_fail;
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
 */

%typemap(default) const char* separators {
    $1 = NULL;
}

%typemap(default) DPS_AcknowledgementHandler {
    $1 = NULL;
}

%typemap(default) (const uint8_t* payload, size_t len) {
    $1 = NULL;
    $2 = 0;
}

%typemap(default) (int16_t ttl) {
    $1 = 0;
}

%typemap(default) (DPS_OnNodeDestroyed cb, void* data) {
    $1 = NULL;
    $2 = NULL;
}

%typemap(default) (const char* key, const char* password) {
    $1 = NULL;
    $2 = NULL;
}

%inline %{
static void _ClearAckHandler(DPS_Publication* pub)
{
    PyObject* cb = (PyObject*)DPS_GetPublicationData(pub);
    Py_XDECREF(cb);
}
%}

/*
 * Dereference the python callback function when freeing a publication
 */
%pythonprepend DPS_DestroyPublication %{
   _ClearAckHandler(pub)
%}

/*
 * Publication acknowledgment function calls into Python
 */
%{
static void AckHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    PyObject* cb = (PyObject*)DPS_GetPublicationData(pub);
    PyObject* pubObj;
    PyObject* ret;
    PyGILState_STATE gilState;

    if (!cb) {
        return;
    }
    /*
     * This callback was called from an external thread so we
     * need to get the Global-Interpreter-Interlock before we
     * can call into the Python interpreter.
     */
    gilState = PyGILState_Ensure();

    pubObj = SWIG_NewPointerObj(SWIG_as_voidptr(pub), SWIGTYPE_p__DPS_Publication, 0);
    ret = PyObject_CallFunction(cb, "Os#", pubObj, payload, len);
    Py_XDECREF(pubObj);
    Py_XDECREF(ret);
    /*
     * All done we can release the lock
     */
    PyGILState_Release(gilState);
}
%}

/*
 * Acknowledgement callback wrapper
 */
%typemap(in) DPS_AcknowledgementHandler {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError,"not a function");
        SWIG_fail;
    }
    if (arg1) {
        DPS_Status ret = DPS_SetPublicationData(arg1, $input);
        if (ret != DPS_OK) {
            PyErr_SetString(PyExc_EnvironmentError,"unable to set callback");
            SWIG_fail;
        }
        Py_INCREF($input);
        $1 = AckHandler;
    }
}

/*
 * Publication received callback call into Python function
 */
%{
void PubHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len)
{
    PyObject* cb = (PyObject*)DPS_GetSubscriptionData(sub);
    PyObject* pubObj;
    PyObject* subObj;
    PyObject* ret;
    PyGILState_STATE gilState;

    if (!cb) {
        DPS_ERRPRINT("Callback is NULL\n");
        return;
    }
    DPS_DBGPRINT("PubHandler\n");
    /*
     * This callback was called from an external thread so we
     * need to get the Global-Interpreter-Interlock before we
     * can call into the Python interpreter.
     */
    gilState = PyGILState_Ensure();

    pubObj = SWIG_NewPointerObj(SWIG_as_voidptr(pub), SWIGTYPE_p__DPS_Publication, 0);
    subObj = SWIG_NewPointerObj(SWIG_as_voidptr(sub), SWIGTYPE_p__DPS_Subscription, 0);
    ret = PyObject_CallFunction(cb, "OOs#", subObj, pubObj, payload, len);
    Py_XDECREF(pubObj);
    Py_XDECREF(subObj);
    Py_XDECREF(ret);
    /*
     * All done we can release the lock
     */
    PyGILState_Release(gilState);
}
%}

%inline %{
static void _ClearPubHandler(DPS_Subscription* sub)
{
    PyObject* cb = (PyObject*)DPS_GetSubscriptionData(sub);
    Py_XDECREF(cb);
}
%}

/*
 * Dereference the python callback function when freeing a publication
 */
%pythonprepend DPS_DestroySubscription %{
   _ClearPubHandler(sub)
%}

/*
 * Publication callback wrapper
 */
%typemap(in) DPS_PublicationHandler {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError,"not a function");
        SWIG_fail;
    }
    if (arg1) {
        DPS_Status ret = DPS_SetSubscriptionData(arg1, $input);
        if (ret != DPS_OK) {
            PyErr_SetString(PyExc_EnvironmentError,"unable to set callback");
            SWIG_fail;
        }
        Py_INCREF($input);
        $1 = PubHandler;
    }
}

%{
static PyObject* UUIDToPyString(const DPS_UUID* uuid)
{
    const char* uuidStr = DPS_UUIDToString(uuid);
    if (uuidStr) {
        return PyString_FromString(uuidStr);
    } else {
        Py_RETURN_NONE;
    }
}
%}

%typemap(in) DPS_UUID* {
    DPS_UUID* uuid = NULL;

    if ($input != Py_None) {
        int j, i;
        if (!PyList_Check($input)) {
            PyErr_SetString(PyExc_TypeError,"DPS_UUID: not a list\n");
            SWIG_fail;
        }
        uuid = (DPS_UUID*)malloc(sizeof(DPS_UUID));
        if (!uuid) {
            PyErr_SetString(PyExc_MemoryError,"DPS_UUID: no memory\n");
            SWIG_fail;
        }
        for (j = 0, i = 0; j < PyList_Size($input); ++j) {
            PyObject *pValue = PyList_GetItem($input, j);
            if (PyInt_Check(pValue) && i < sizeof(DPS_UUID)) {
                int32_t v = PyInt_AsLong(pValue);
                if (v >= 0 && v <= 255) {
                    uuid->val[i++] = (uint8_t)v;
                } else {
                    PyErr_SetString(PyExc_TypeError,"uuid values must be in range 0..255");
                    free(uuid);
                    SWIG_fail;
                }
            } else {
                PyErr_SetString(PyExc_TypeError,"value is not int type or len > uuid");
                free(uuid);
                SWIG_fail;
            }
        }
    }
    $1 = uuid;
}

%typemap(freearg) DPS_UUID* {
    if ($1) {
        free($1);
    }
}

%typemap(out) DPS_UUID* {
    $result = UUIDToPyString($1);
}

%typemap(out) const DPS_UUID* {
    $result = UUIDToPyString($1);
}

/*
 * Used in DPS_SetContentKey.
 */
%typemap(in) (const DPS_Key* key) {
    DPS_Key* k = NULL;

    if ($input != Py_None) {
        if (!PyList_Check($input)) {
            PyErr_SetString(PyExc_TypeError, "key should be a list\n");
            SWIG_fail;
        }
        k = calloc(1, sizeof(DPS_Key));
        if (!k) {
            SWIG_fail;
        }
        k->type = DPS_KEY_SYMMETRIC;
        k->symmetric.len = PyList_Size($input);
        k->symmetric.key = calloc(k->symmetric.len, sizeof(uint8_t));
        if (!k->symmetric.key) {
            free(k);
            SWIG_fail;
        }

        for (size_t i = 0; i < k->symmetric.len; ++i) {
            PyObject *pValue = PyList_GetItem($input, i);
            if (PyInt_Check(pValue)) {
                int32_t v = PyInt_AsLong(pValue);
                if (v >= 0 && v <= 255) {
                    ((uint8_t*)k->symmetric.key)[i] = (uint8_t)v;
                } else {
                    PyErr_SetString(PyExc_TypeError, "key values must be a list of int in range 0..255");
                    free((uint8_t*)k->symmetric.key);
                    free(k);
                    SWIG_fail;
                }
            } else {
                PyErr_SetString(PyExc_TypeError, "key is not list of ints");
                free((uint8_t*)k->symmetric.key);
                free(k);
                SWIG_fail;
            }

        }
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

    if ($input != Py_None) {
        int alloc = SWIG_NEWOBJ;
        kid = calloc(1, sizeof(DPS_KeyId));
        if (!kid) {
            SWIG_fail;
        }
        if (PyList_Check($input)) {
            kid->len = PyList_Size($input);
            kid->id = calloc(kid->len, sizeof(uint8_t));
            if (!kid->id) {
                free(kid);
                SWIG_fail;
            }

            for (size_t i = 0; i < kid->len; ++i) {
                PyObject *pValue = PyList_GetItem($input, i);
                if (PyInt_Check(pValue)) {
                    int32_t v = PyInt_AsLong(pValue);
                    if (v >= 0 && v <= 255) {
                        ((uint8_t*)kid->id)[i] = (uint8_t)v;
                    } else {
                        PyErr_SetString(PyExc_TypeError, "keyId values must be a list of int in range 0..255");
                        free((uint8_t*)kid->id);
                        free(kid);
                        SWIG_fail;
                    }
                } else {
                    PyErr_SetString(PyExc_TypeError, "keyId is not list of ints");
                    free((uint8_t*)kid->id);
                    free(kid);
                    SWIG_fail;
                }

            }
        } else if (SWIG_AsCharPtrAndSize($input, (char**)&kid->id, &kid->len, &alloc) != SWIG_OK) {
            PyErr_SetString(PyExc_TypeError, "keyId should be a list or string\n");
            free(kid);
            SWIG_fail;
        }
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

/*
 * Disallow NULL for these pointer types
 */
%apply Pointer NONNULL { DPS_Node* };
%apply Pointer NONNULL { DPS_Subscription* };
%apply Pointer NONNULL { DPS_Publication* };
%apply Pointer NONNULL { DPS_NodeAddress* };

/*
 * The DPS public header files
 */
%include <dps/err.h>
%include <dps/dps.h>
%include <dps/synchronous.h>

/*
 * Module initialization
 */
%init %{
    /* Must be called during module initialization to enable DPS callbacks */
    PyEval_InitThreads();
    DPS_Debug = 0;
%}
