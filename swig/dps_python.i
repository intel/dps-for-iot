
%module dps
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
 * Functions that must not be exposed in Python
 */
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
 * Module is called dps we don't need the DPS prefix on every function
 */
%rename("%(strip:[DPS_])s") "";

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
%typemap(in) (uint8_t* key, size_t keyLen) {
    uint8_t* key = NULL;
    size_t keyLen = 0;

    if ($input != Py_None) {
        if (!PyList_Check($input)) {
            PyErr_SetString(PyExc_TypeError, "key should be a list\n");
            SWIG_fail;
        }
        keyLen = PyList_Size($input);

        key = calloc(keyLen, sizeof(uint8_t));
        if (!key) {
            SWIG_fail;
        }

        for (size_t i = 0; i < keyLen; ++i) {
            PyObject *pValue = PyList_GetItem($input, i);
            if (PyInt_Check(pValue)) {
                int32_t v = PyInt_AsLong(pValue);
                if (v >= 0 && v <= 255) {
                    key[i] = (uint8_t)v;
                } else {
                    PyErr_SetString(PyExc_TypeError, "key values must be a list of int in range 0..255");
                    free(key);
                    SWIG_fail;
                }
            } else {
                PyErr_SetString(PyExc_TypeError, "key is not list of ints");
                free(key);
                SWIG_fail;
            }

        }
    }

    $1 = key;
    $2 = keyLen;
}

%typemap(freearg) (uint8_t* key, size_t keyLen) {
    free($1);
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
