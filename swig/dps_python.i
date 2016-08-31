
%module dps
%{
#include "dps.h"
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
 * Module is called dps we don't need the DPS prefix on every function
 */
%rename("%(strip:[DPS_])s") "";

/*
 * Mapping for types from stdint.h
 */
%typemap(in) uint8_t* = char*;
%typemap(in) int16_t = int;


/*
 * This allows topic strings to be expressed as a list of strings
 */
%typemap(in) (char* const* topics, size_t numTopics) {
    /* Expecting a list of strings */
    if (PyList_Check($input)) {
        int i;
        int sz = PyList_Size($input);
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

/*
 * For now just allow strings as payloads.
 * Eventually need to figure out how to handle binary data.
 */
%typemap(in) (uint8_t* payload, size_t len) {
    /* Only supprting strings for now */
    if (PyString_Check($input)) {
        $2 = PyString_Size($input);
        $1 = (uint8_t*)malloc(($2 + 1) * sizeof(uint8_t*));
        memcpy($1, PyString_AsString($input), $2);
        $1[$2] = 0;
    } else {
        PyErr_SetString(PyExc_TypeError,"not a string");
        return NULL;
    }
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

/*
 * Publication acknowledgment function calls into Python
 */
%inline %{
void AckHandler(DPS_Publication* pub, uint8_t* payload, size_t len)
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
    Py_DECREF(cb);
    /*
     * All done we can release the lock
     */
    PyGILState_Release(gilState);
}

void AckHandlerCleanup(DPS_Publication* pub)
{
    PyObject* cb = (PyObject*)DPS_GetPublicationData(pub);
    if (cb) {
        Py_DECREF(cb);
        DPS_SetPublicationData(pub, NULL);
    }
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
%inline %{
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
    Py_DECREF(cb);
    /*
     * All done we can release the lock
     */
    PyGILState_Release(gilState);
}
%}

%inline %{
void PubHandlerCleanup(DPS_Subscription* sub)
{
    PyObject* cb = (PyObject*)DPS_GetSubscriptionData(sub);
    if (cb) {
        Py_DECREF(cb);
        DPS_SetSubscriptionData(sub, NULL);
    }
}
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
 *
 * Note we need to undef the header guards otherwise we get nothing
 */
#undef _DPS_UUID_H
%include "dps_uuid.h"
#undef _DPS_ERR_H
%include "dps_err.h"
#undef _DPS_H
%include "dps.h"

/*
 * Module initialization
 */
%init %{
    /* Must be called during module initialization to enable DPS callbacks */
    PyEval_InitThreads();
%}
