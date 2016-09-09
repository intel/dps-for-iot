
%module dps
%{
#include "dps.h"
#include "dps_synchronous.h"
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
%typemap(in) uint16_t = unsigned int;
%typemap(out) uint32_t = unsigned long;


/*
 * Debug control
 */
%inline %{
int DPS_Debug;
%}

/*
 * This allows topic strings to be expressed as a list of strings
 */
%typemap(in) (char* const* topics, size_t numTopics) {
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
                free($1);
                return NULL;
            }
        }
        $1[i] = 0;
        $2 = sz;
    } else {
        PyErr_SetString(PyExc_TypeError,"not a list");
        return NULL;
    }
}

/* 
 * Post function call cleanup for topic strings
 */
%typemap(freearg) (char* const* topics, size_t numTopics) {
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
        memcpy(str, PyString_AsString(py), sz);
        str[sz] = 0;
        *len = (size_t)sz;
    } else {
        PyErr_SetString(PyExc_TypeError,"not a string");
    }
    return str;
}
%}

%typemap(in) (uint8_t* pubPayload, size_t len) {
    $1 = AllocPayload($input, &$2);
    if (!$1) {
        return NULL;
    }
}

%typemap(in) (uint8_t* ackPayload, size_t len) {
    $1 = AllocPayload($input, &$2);
    if (!$1) {
        return NULL;
    }
}

%typemap(freearg) (uint8_t* ackPayload, size_t len) {
    free($1);
}

/*
 * The following pair of typemaps cleanup old publication payloads
 */
%typemap(in, numinputs=0) uint8_t** oldPayload (uint8_t* old) {
    $1 = &old;
}

%typemap(argout) (uint8_t** oldPayload) {
    if (*$1) {
        free(*$1);
    }
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

%typemap(default) (int16_t ttl, uint8_t** oldPayload) {
    $1 =  0;
    $2 = NULL;
}

%typemap(default) uint8_t** oldPayload {
    $1 = NULL;
}

%typemap(default) (uint8_t* payload, size_t len) {
    $1 = NULL;
    $2 = 0;
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
        return NULL;
    }
    if (arg1) {
        DPS_Status ret = DPS_SetPublicationData(arg1, $input);
        if (ret != DPS_OK) {
            PyErr_SetString(PyExc_EnvironmentError,"unable to set callback");
            return NULL;
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
        return;
    }
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
        return NULL;
    }
    if (arg1) {
        DPS_Status ret = DPS_SetSubscriptionData(arg1, $input);
        if (ret != DPS_OK) {
            PyErr_SetString(PyExc_EnvironmentError,"unable to set callback");
            return NULL;
        }
        Py_INCREF($input);
        $1 = PubHandler;
    }
}

%{
static PyObject* UUIDToPyString(DPS_UUID* uuid)
{
    const char* uuidStr = DPS_UUIDToString(uuid);
    if (uuidStr) {
        return PyString_FromString(uuidStr);
    } else {
        Py_RETURN_NONE;
    }
}
%}

%typemap(out) DPS_UUID* {
    $result = UUIDToPyString($1);
}

/*
 * Disallow NULL for these pointer types
 */
%apply Pointer NONNULL { DPS_Node* };
%apply Pointer NONNULL { DPS_UUID* };
%apply Pointer NONNULL { DPS_Subscription* };
%apply Pointer NONNULL { DPS_Publication* };
%apply Pointer NONNULL { DPS_NodeAddress* };

/*
 * The DPS public header files
 */
%include "dps_err.h"
%include "dps.h"
%include "dps_synchronous.h"

/*
 * Module initialization
 */
%init %{
    /* Must be called during module initialization to enable DPS callbacks */
    PyEval_InitThreads();
    DPS_Debug = 0;
%}
