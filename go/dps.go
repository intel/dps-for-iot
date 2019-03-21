package dps

import (
	"sync"
	"unsafe"
)

/*
 #include <stdlib.h>
 #include <string.h>
 #include <uv.h>
 #include <dps/dbg.h>
 #include <dps/dps.h>
 #include <dps/json.h>
 #include <dps/synchronous.h>

 extern DPS_Status goKeyAndIdHandler(DPS_KeyStoreRequest* request);
 static DPS_Status keyAndIdHandler(DPS_KeyStoreRequest* request) {
         return goKeyAndIdHandler(request);
 }
 extern DPS_Status goKeyHandler(DPS_KeyStoreRequest* request, DPS_KeyId* keyId);
 static DPS_Status keyHandler(DPS_KeyStoreRequest* request, const DPS_KeyId* keyId) {
         return goKeyHandler(request, (DPS_KeyId*)keyId);
 }
 extern DPS_Status goEphemeralKeyHandler(DPS_KeyStoreRequest* request, DPS_Key* key);
 static DPS_Status ephemeralKeyHandler(DPS_KeyStoreRequest* request, const DPS_Key* key) {
         return goEphemeralKeyHandler(request, (DPS_Key*)key);
 }
 extern DPS_Status goCAHandler(DPS_KeyStoreRequest* request);
 static DPS_Status caHandler(DPS_KeyStoreRequest* request) {
         return goCAHandler(request);
 }

 static DPS_KeyStore* createKeyStore() {
         return DPS_CreateKeyStore(keyAndIdHandler, keyHandler, ephemeralKeyHandler, caHandler);
 }

 static DPS_KeyId* makeKeyId(uint8_t* id, size_t len) {
         DPS_KeyId* kid;
         kid = malloc(sizeof(DPS_KeyId));
         if (kid) {
                 kid->id = id;
                 kid->len = len;
         }
         return kid;
 }
 static DPS_Key* makeKeySymmetric(uint8_t* key, size_t len) {
         DPS_Key* k;
         k = calloc(1, sizeof(DPS_Key));
         if (k) {
                 k->type = DPS_KEY_SYMMETRIC;
                 if (key) {
                         k->symmetric.key = key;
                         k->symmetric.len = len;
                 }
         }
         return k;
 }
 static DPS_Key* makeKeyEC(DPS_ECCurve curve, uint8_t* x, uint8_t* y, uint8_t* d) {
         DPS_Key* k;
         k = calloc(1, sizeof(DPS_Key));
         if (k) {
                 k->type = DPS_KEY_EC;
                 k->ec.curve = curve;
                 k->ec.x = x;
                 k->ec.y = y;
                 k->ec.d = d;
         }
         return k;
 }
 static DPS_Key* makeKeyCert(char *cert, char *privateKey, char *password) {
         DPS_Key* k;
         k = calloc(1, sizeof(DPS_Key));
         if (k) {
                 k->type = DPS_KEY_EC_CERT;
                 k->cert.cert = cert;
                 k->cert.privateKey = privateKey;
                 k->cert.password = password;
         }
         return k;
 }
 static void freeKey(DPS_Key* k) {
         if (k) {
                 switch (k->type) {
                 case DPS_KEY_SYMMETRIC:
                         if (k->symmetric.key) free((char*)k->symmetric.key);
                         break;
                 case DPS_KEY_EC:
                         if (k->ec.x) free((char*)k->ec.x);
                         if (k->ec.y) free((char*)k->ec.y);
                         if (k->ec.d) free((char*)k->ec.d);
                         break;
                 case DPS_KEY_EC_CERT:
                         if (k->cert.cert) free((char*)k->cert.cert);
                         if (k->cert.privateKey) free((char*)k->cert.privateKey);
                         if (k->cert.password) free((char*)k->cert.password);
                         break;
                 default:
                         break;
                 }
                 free(k);
         }
 }

 extern void goOnNodeDestroyed(DPS_Node* node, uintptr_t data);
 static void onNodeDestroyed(DPS_Node* node, void* data) {
         goOnNodeDestroyed(node, (uintptr_t)data);
 }

 static DPS_Status destroyNode(DPS_Node* node, uintptr_t data) {
         return DPS_DestroyNode(node, onNodeDestroyed, (void*)data);
 }

 extern void goOnLinkComplete(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, uintptr_t data);
 static void onLinkComplete(DPS_Node* node, DPS_NodeAddress* addr, DPS_Status status, void* data) {
         goOnLinkComplete(node, addr, status, (uintptr_t)data);
 }

 static DPS_Status link(DPS_Node* node, const char* addrText, uintptr_t data) {
         return DPS_Link(node, addrText, onLinkComplete, (void*)data);
 }

 extern void goOnUnlinkComplete(DPS_Node* node, DPS_NodeAddress* addr, uintptr_t data);
 static void onUnlinkComplete(DPS_Node* node, const DPS_NodeAddress* addr, void* data) {
         goOnUnlinkComplete(node, (DPS_NodeAddress*)addr, (uintptr_t)data);
 }

 // mangle the name to avoid conflicts with mingw
 static DPS_Status unlink_(DPS_Node* node, const DPS_NodeAddress* addr, uintptr_t data) {
         return DPS_Unlink(node, addr, onUnlinkComplete, (void*)data);
 }

 extern void goOnResolveAddressComplete(DPS_Node* node, DPS_NodeAddress* addr, uintptr_t data);
 static void onResolveAddressComplete(DPS_Node* node, const DPS_NodeAddress* addr, void* data) {
         goOnResolveAddressComplete(node, (DPS_NodeAddress*)addr, (uintptr_t)data);
 }

 static DPS_Status resolveAddress(DPS_Node* node, char* host, char* service, uintptr_t data) {
         return DPS_ResolveAddress(node, host, service, onResolveAddressComplete, (void*)data);
 }

 static char** makeTopics(size_t n) {
         return calloc(sizeof(char*), n);
 }

 static void setTopic(char **ts, char *t, size_t i) {
         ts[i] = t;
 }

 static void freeTopics(char **ts, size_t n) {
         size_t i;
         for (i = 0; i < n; i++)
                 free(ts[i]);
         free(ts);
 }

 extern void goAcknowledgementHandler(DPS_Publication* pub, uint8_t* payload, size_t len);
 static void acknowledgementHandler(DPS_Publication* pub, uint8_t* payload, size_t len) {
         goAcknowledgementHandler(pub, payload, len);
 }

 static DPS_Status initPublication(DPS_Publication* pub, const char** topics, size_t numTopics, int noWildCard,
         const DPS_KeyId* keyId) {
         return DPS_InitPublication(pub, topics, numTopics, noWildCard, keyId, acknowledgementHandler);
 }

 extern void goPublicationHandler(DPS_Subscription* sub, DPS_Publication* pub, uint8_t* payload, size_t len);
 static void publicationHandler(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* payload, size_t len) {
         goPublicationHandler(sub, (DPS_Publication*)pub, payload, len);
 }

 static DPS_Status subscribe(DPS_Subscription* sub) {
         return DPS_Subscribe(sub, publicationHandler);
 }

 static DPS_Buffer* makeBuffers(size_t n) {
         return calloc(sizeof(DPS_Buffer), n);
 }

 extern void goPublishBufsComplete(DPS_Publication* pub, uintptr_t data);
 static void publishBufsComplete(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status, void* data)
 {
         goPublishBufsComplete(pub, (uintptr_t)data);
 }

 static DPS_Status publishBufs(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, int16_t ttl, uintptr_t data) {
         return DPS_PublishBufs(pub, bufs, numBufs, ttl, publishBufsComplete, (void*)data);
 }

 extern void goAckPublicationBufsComplete(DPS_Publication* pub, uintptr_t data);
 static void ackPublicationBufsComplete(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, DPS_Status status, void* data)
 {
         goAckPublicationBufsComplete(pub, (uintptr_t)data);
 }

 static DPS_Status ackPublicationBufs(DPS_Publication* pub, const DPS_Buffer* bufs, size_t numBufs, uintptr_t data) {
         return DPS_AckPublicationBufs(pub, bufs, numBufs, ackPublicationBufsComplete, (void*)data);
 }

*/
import "C"

// need a registry to hold onto Go values used inside DPS else they may get gc'd
type registry struct {
	mutex  sync.Mutex
	values map[uintptr]interface{}
	handle uintptr
}

func makeRegistry() (r *registry) {
	r = new(registry)
	r.values = make(map[uintptr]interface{})
	return
}
func (r *registry) register(fn interface{}) uintptr {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.handle++
	for r.handle != 0 && r.values[r.handle] != nil {
		r.handle++
	}
	r.values[r.handle] = fn
	return r.handle
}
func (r *registry) unregister(handle uintptr) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	delete(r.values, handle)
}
func (r *registry) lookup(handle uintptr) interface{} {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.values[handle]
}

var reg = makeRegistry()

func Debug() int {
	return int(C.DPS_Debug)
}
func SetDebug(debug int) {
	C.DPS_Debug = C.int(debug)
}

type NodeAddress C.DPS_NodeAddress

func NodeAddrToString(addr *NodeAddress) string {
	caddr := (*C.DPS_NodeAddress)(addr)
	return C.GoString(C.DPS_NodeAddrToString(caddr))
}
func CreateAddress() *NodeAddress {
	return (*NodeAddress)(C.DPS_CreateAddress())
}
func SetAddress(addr *NodeAddress, hostport string) *NodeAddress {
	caddr := (*C.DPS_NodeAddress)(addr)
	chostport := C.CString(hostport)
	defer C.free(unsafe.Pointer(chostport))
	return (*NodeAddress)(C.DPS_SetAddress(caddr, chostport))
}
func CopyAddress(dest *NodeAddress, src *NodeAddress) {
	cdest := (*C.DPS_NodeAddress)(dest)
	csrc := (*C.DPS_NodeAddress)(src)
	C.DPS_CopyAddress(cdest, csrc)
}
func DestroyAddress(addr *NodeAddress) {
	caddr := (*C.DPS_NodeAddress)(addr)
	C.DPS_DestroyAddress(caddr)
}

type KeyType int

const (
	KEY_SYMMETRIC KeyType = C.DPS_KEY_SYMMETRIC
	KEY_EC                = C.DPS_KEY_EC
	KEY_EC_CERT           = C.DPS_KEY_EC_CERT
)

const AES_256_KEY_LEN int = 32
const (
	EC_CURVE_RESERVED ECCurve = C.DPS_EC_CURVE_RESERVED
	EC_CURVE_P384             = C.DPS_EC_CURVE_P384
	EC_CURVE_P521             = C.DPS_EC_CURVE_P521
)

type KeySymmetric []byte

func (k KeySymmetric) keyType() KeyType { return KEY_SYMMETRIC }

type ECCurve int
type KeyEC struct {
	Curve ECCurve
	X     []byte
	Y     []byte
	D     []byte
}

func (k KeyEC) keyType() KeyType { return KEY_EC }

type KeyCert struct {
	Cert       string
	PrivateKey string
	Password   string
}

func (k KeyCert) keyType() KeyType { return KEY_EC_CERT }

type Key interface {
	keyType() KeyType
}
type KeyId []byte
type KeyStoreRequest C.DPS_KeyStoreRequest
type KeyAndIdHandler func(request *KeyStoreRequest) int
type KeyHandler func(request *KeyStoreRequest, keyId KeyId) int
type EphemeralKeyHandler func(request *KeyStoreRequest, key Key) int
type CAHandler func(request *KeyStoreRequest) int

type KeyStore interface {
	chandle() *C.DPS_KeyStore
}

type userKeyStore struct {
	handle              uintptr
	ckeyStore           *C.DPS_KeyStore
	keyAndIdHandler     KeyAndIdHandler
	keyHandler          KeyHandler
	ephemeralKeyHandler EphemeralKeyHandler
	caHandler           CAHandler
}

func (ks userKeyStore) chandle() *C.DPS_KeyStore { return ks.ckeyStore }

func makeKeyId(keyId KeyId) *C.DPS_KeyId {
	return C.makeKeyId((*C.uint8_t)(&keyId[0]), C.size_t(len(keyId)))
}

func makeKey(key Key) *C.DPS_Key {
	// no defer below, freeKey will take care of the memory
	switch key.(type) {
	case KeySymmetric:
		k, _ := key.(KeySymmetric)
		var ck *C.uint8_t
		if len(k) != 0 {
			ck = (*C.uint8_t)(C.CBytes(k))
		}
		return C.makeKeySymmetric(ck, C.size_t(len(k)))
	case KeyEC:
		k, _ := key.(KeyEC)
		var cx, cy, cd *C.uint8_t
		if len(k.X) != 0 {
			cx = (*C.uint8_t)(C.CBytes(k.X))
		}
		if len(k.Y) != 0 {
			cy = (*C.uint8_t)(C.CBytes(k.Y))
		}
		if len(k.D) != 0 {
			cd = (*C.uint8_t)(C.CBytes(k.D))
		}
		return C.makeKeyEC(C.DPS_ECCurve(k.Curve), cx, cy, cd)
	case KeyCert:
		k, _ := key.(KeyCert)
		var ccert, cprivateKey, cpassword *C.char
		if len(k.Cert) != 0 {
			ccert = C.CString(k.Cert)
		}
		if len(k.PrivateKey) != 0 {
			cprivateKey = C.CString(k.PrivateKey)
		}
		if len(k.Password) != 0 {
			cpassword = C.CString(k.Password)
		}
		return C.makeKeyCert(ccert, cprivateKey, cpassword)
	}
	panic("invalid key type")
}

func SetKeyAndId(request *KeyStoreRequest, key Key, keyId KeyId) int {
	crequest := (*C.DPS_KeyStoreRequest)(request)
	ckey := makeKey(key)
	defer C.freeKey(ckey)
	ckeyId := C.DPS_KeyId{(*C.uint8_t)(&keyId[0]), C.size_t(len(keyId))}
	return int(C.DPS_SetKeyAndId(crequest, ckey, &ckeyId))
}
func SetKey(request *KeyStoreRequest, key Key) int {
	crequest := (*C.DPS_KeyStoreRequest)(request)
	ckey := makeKey(key)
	defer C.freeKey(ckey)
	return int(C.DPS_SetKey(crequest, ckey))
}
func SetCA(request *KeyStoreRequest, ca string) int {
	crequest := (*C.DPS_KeyStoreRequest)(request)
	cca := C.CString(ca)
	defer C.free(unsafe.Pointer(cca))
	return int(C.DPS_SetCA(crequest, cca))
}
func KeyStoreHandle(request *KeyStoreRequest) KeyStore {
	crequest := (*C.DPS_KeyStoreRequest)(request)
	ckeyStore := C.DPS_KeyStoreHandle(crequest)
	ks, ok := reg.lookup(uintptr(C.DPS_GetKeyStoreData(ckeyStore))).(*userKeyStore)
	if ok {
		return ks
	} else {
		return nil
	}
}
func CreateKeyStore(keyAndIdHandler KeyAndIdHandler, keyHandler KeyHandler,
	ephemeralKeyHandler EphemeralKeyHandler, caHandler CAHandler) (keyStore KeyStore) {
	ckeyStore := C.createKeyStore()
	if ckeyStore != nil {
		ks := new(userKeyStore)
		ks.handle = reg.register(ks)
		ks.ckeyStore = ckeyStore
		ks.keyAndIdHandler = keyAndIdHandler
		ks.keyHandler = keyHandler
		ks.ephemeralKeyHandler = ephemeralKeyHandler
		ks.caHandler = caHandler
		C.DPS_SetKeyStoreData(ckeyStore, unsafe.Pointer(ks.handle))
		keyStore = ks
	}
	return
}
func DestroyKeyStore(keyStore KeyStore) {
	switch keyStore.(type) {
	case *userKeyStore:
		ks, _ := keyStore.(*userKeyStore)
		reg.unregister(ks.handle)
		cks := (*C.DPS_KeyStore)(ks.ckeyStore)
		C.DPS_DestroyKeyStore(cks)
	case *memoryKeyStore:
		ks, _ := keyStore.(*memoryKeyStore)
		cks := (*C.DPS_MemoryKeyStore)(ks.ckeyStore)
		C.DPS_DestroyMemoryKeyStore(cks)
	}
}

//export goKeyAndIdHandler
func goKeyAndIdHandler(crequest *C.DPS_KeyStoreRequest) C.DPS_Status {
	request := (*KeyStoreRequest)(crequest)
	ckeyStore := (*C.DPS_KeyStore)(C.DPS_KeyStoreHandle(crequest))
	ks, ok := reg.lookup(uintptr(C.DPS_GetKeyStoreData(ckeyStore))).(*userKeyStore)
	if !ok {
		return ERR_FAILURE
	} else if ks.keyAndIdHandler == nil {
		return ERR_NOT_IMPLEMENTED
	} else {
		return C.DPS_Status(ks.keyAndIdHandler(request))
	}
}

//export goKeyHandler
func goKeyHandler(crequest *C.DPS_KeyStoreRequest, ckeyId *C.DPS_KeyId) C.DPS_Status {
	request := (*KeyStoreRequest)(crequest)
	ckeyStore := (*C.DPS_KeyStore)(C.DPS_KeyStoreHandle(crequest))
	var keyId KeyId
	if ckeyId != nil && ckeyId.id != nil {
		keyId = (*[1 << 30]byte)(unsafe.Pointer(ckeyId.id))[:ckeyId.len:ckeyId.len]
	}
	ks, ok := reg.lookup(uintptr(C.DPS_GetKeyStoreData(ckeyStore))).(*userKeyStore)
	if !ok {
		return ERR_FAILURE
	} else if ks.keyHandler == nil {
		return ERR_NOT_IMPLEMENTED
	} else {
		return C.DPS_Status(ks.keyHandler(request, keyId))
	}
}

//export goEphemeralKeyHandler
func goEphemeralKeyHandler(crequest *C.DPS_KeyStoreRequest, ckey *C.DPS_Key) C.DPS_Status {
	request := (*KeyStoreRequest)(crequest)
	ckeyStore := (*C.DPS_KeyStore)(C.DPS_KeyStoreHandle(crequest))
	var key Key
	switch ckey._type {
	case C.DPS_KEY_SYMMETRIC:
		symmetric := (*C.DPS_KeySymmetric)(unsafe.Pointer(&ckey.anon0))
		var data []byte
		if symmetric.key != nil {
			len := symmetric.len
			data = (*[1 << 30]byte)(unsafe.Pointer(symmetric.key))[:len:len]
		}
		key = KeySymmetric(data)
	case C.DPS_KEY_EC:
		ec := (*C.DPS_KeyEC)(unsafe.Pointer(&ckey.anon0))
		var x, y, d []byte
		if ec.x != nil {
			x = (*[1 << 30]byte)(unsafe.Pointer(ec.x))[:66:66]
		}
		if ec.y != nil {
			y = (*[1 << 30]byte)(unsafe.Pointer(ec.y))[:66:66]
		}
		if ec.d != nil {
			d = (*[1 << 30]byte)(unsafe.Pointer(ec.d))[:66:66]
		}
		key = KeyEC{ECCurve(ec.curve), x, y, d}
	case C.DPS_KEY_EC_CERT:
		cert := (*C.DPS_KeyCert)(unsafe.Pointer(&ckey.anon0))
		var privateKey, password string
		if cert.privateKey != nil {
			privateKey = C.GoString(cert.privateKey)
		}
		if cert.password != nil {
			password = C.GoString(cert.password)
		}
		key = KeyCert{C.GoString(cert.cert), privateKey, password}
	}
	ks, ok := reg.lookup(uintptr(C.DPS_GetKeyStoreData(ckeyStore))).(*userKeyStore)
	if !ok {
		return ERR_FAILURE
	} else if ks.ephemeralKeyHandler == nil {
		return ERR_NOT_IMPLEMENTED
	} else {
		return C.DPS_Status(ks.ephemeralKeyHandler(request, key))
	}
}

//export goCAHandler
func goCAHandler(crequest *C.DPS_KeyStoreRequest) C.DPS_Status {
	request := (*KeyStoreRequest)(crequest)
	ckeyStore := (*C.DPS_KeyStore)(C.DPS_KeyStoreHandle(crequest))
	ks, ok := reg.lookup(uintptr(C.DPS_GetKeyStoreData(ckeyStore))).(*userKeyStore)
	if !ok {
		return ERR_FAILURE
	} else if ks.caHandler == nil {
		return ERR_NOT_IMPLEMENTED
	} else {
		return C.DPS_Status(ks.caHandler(request))
	}
}

type memoryKeyStore struct {
	ckeyStore *C.DPS_MemoryKeyStore
}

func (ks memoryKeyStore) chandle() *C.DPS_KeyStore {
	return C.DPS_MemoryKeyStoreHandle((*C.DPS_MemoryKeyStore)(ks.ckeyStore))
}

func CreateMemoryKeyStore() (keyStore KeyStore) {
	ckeyStore := C.DPS_CreateMemoryKeyStore()
	if ckeyStore != nil {
		ks := new(memoryKeyStore)
		ks.ckeyStore = ckeyStore
		keyStore = ks
	}
	return
}
func SetContentKey(keyStore KeyStore, keyId KeyId, key Key) int {
	ks, ok := keyStore.(*memoryKeyStore)
	if !ok {
		return ERR_ARGS
	}
	ckeyId := makeKeyId(keyId)
	if ckeyId == nil {
		return ERR_RESOURCES
	}
	defer C.free(unsafe.Pointer(ckeyId))
	ckey := makeKey(key)
	defer C.freeKey(ckey)
	return int(C.DPS_SetContentKey(ks.ckeyStore, ckeyId, ckey))
}
func SetNetworkKey(keyStore KeyStore, keyId KeyId, key Key) int {
	ks, ok := keyStore.(*memoryKeyStore)
	if !ok {
		return ERR_ARGS
	}
	ckeyId := makeKeyId(keyId)
	if ckeyId == nil {
		return ERR_RESOURCES
	}
	defer C.free(unsafe.Pointer(ckeyId))
	ckey := makeKey(key)
	defer C.freeKey(ckey)
	return int(C.DPS_SetNetworkKey(ks.ckeyStore, ckeyId, ckey))
}
func SetTrustedCA(keyStore KeyStore, ca string) int {
	ks, ok := keyStore.(*memoryKeyStore)
	if !ok {
		return ERR_ARGS
	}
	cca := C.CString(ca)
	defer C.free(unsafe.Pointer(cca))
	return int(C.DPS_SetTrustedCA(ks.ckeyStore, cca))
}
func SetCertificate(keyStore KeyStore, cert string, privateKey *string, password *string) int {
	ks, ok := keyStore.(*memoryKeyStore)
	if !ok {
		return ERR_ARGS
	}
	ccert := C.CString(cert)
	defer C.free(unsafe.Pointer(ccert))
	var cprivateKey, cpassword *C.char
	if privateKey != nil {
		cprivateKey = C.CString(*privateKey)
		defer C.free(unsafe.Pointer(cprivateKey))
	}
	if password != nil {
		cpassword = C.CString(*password)
		defer C.free(unsafe.Pointer(cpassword))
	}
	return int(C.DPS_SetCertificate(ks.ckeyStore, ccert, cprivateKey, cpassword))
}

const MCAST_PUB_DISALBED = C.DPS_MCAST_PUB_DISABLED
const MCAST_PUB_ENABLE_SEND = C.DPS_MCAST_PUB_ENABLE_SEND
const MCAST_PUB_ENABLE_RECV = C.DPS_MCAST_PUB_ENABLE_RECV

type Node C.DPS_Node

func CreateNode(separators string, keyStore KeyStore, keyId KeyId) *Node {
	cseparators := C.CString(separators)
	defer C.free(unsafe.Pointer(cseparators))
	var ckeyStore *C.DPS_KeyStore
	if keyStore != nil {
		ckeyStore = keyStore.chandle()
	}
	var ckeyId *C.DPS_KeyId
	if len(keyId) > 0 {
		ckeyId = makeKeyId(keyId)
		if ckeyId == nil {
			return nil
		}
		defer C.free(unsafe.Pointer(ckeyId))
	}
	return (*Node)(C.DPS_CreateNode(cseparators, ckeyStore, ckeyId))
}

func StartNode(node *Node, mcastPub int, listenAddr *NodeAddress) int {
	cnode := (*C.DPS_Node)(node)
	clistenAddr := (*C.DPS_NodeAddress)(listenAddr)
	return int(C.DPS_StartNode(cnode, C.int(mcastPub), clistenAddr))
}

type OnNodeDestroyed func(*Node)

func DestroyNode(node *Node, cb OnNodeDestroyed) int {
	cnode := (*C.DPS_Node)(node)
	handle := reg.register(cb)
	return int(C.destroyNode(cnode, C.uintptr_t(handle)))
}

//export goOnNodeDestroyed
func goOnNodeDestroyed(cnode *C.DPS_Node, handle uintptr) {
	cb, ok := reg.lookup(handle).(OnNodeDestroyed)
	if ok {
		cb((*Node)(cnode))
		reg.unregister(handle)
	}
}

func SetNodeSubscriptionUpdateDelay(node *Node, subsRateMsecs uint32) {
	cnode := (*C.DPS_Node)(node)
	C.DPS_SetNodeSubscriptionUpdateDelay(cnode, C.uint32_t(subsRateMsecs))
}

func GetListenAddress(node *Node) *NodeAddress {
	cnode := (*C.DPS_Node)(node)
	return (*NodeAddress)(C.DPS_GetListenAddress(cnode))
}

func GetListenAddressString(node *Node) string {
	cnode := (*C.DPS_Node)(node)
	return C.GoString(C.DPS_GetListenAddressString(cnode))
}

type OnLinkComplete func(node *Node, addr *NodeAddress, status int)

func Link(node *Node, addrText string, cb OnLinkComplete) int {
	cnode := (*C.DPS_Node)(node)
	caddrText := C.CString(addrText)
	defer C.free(unsafe.Pointer(caddrText))
	handle := reg.register(cb)
	return int(C.link(cnode, caddrText, C.uintptr_t(handle)))
}

//export goOnLinkComplete
func goOnLinkComplete(cnode *C.DPS_Node, caddr *C.DPS_NodeAddress, status C.DPS_Status, handle uintptr) {
	node := (*Node)(cnode)
	addr := (*NodeAddress)(caddr)
	cb, ok := reg.lookup(handle).(OnLinkComplete)
	if ok {
		cb(node, addr, int(status))
		reg.unregister(handle)
	}
}

type OnUnlinkComplete func(node *Node, addr *NodeAddress)

func Unlink(node *Node, addr *NodeAddress, cb OnUnlinkComplete) int {
	cnode := (*C.DPS_Node)(node)
	caddr := (*C.DPS_NodeAddress)(addr)
	handle := reg.register(cb)
	return int(C.unlink_(cnode, caddr, C.uintptr_t(handle)))
}

//export goOnUnlinkComplete
func goOnUnlinkComplete(cnode *C.DPS_Node, caddr *C.DPS_NodeAddress, handle uintptr) {
	node := (*Node)(cnode)
	addr := (*NodeAddress)(caddr)
	cb, ok := reg.lookup(handle).(OnUnlinkComplete)
	if ok {
		cb(node, addr)
		reg.unregister(handle)
	}
}

type OnResolveAddressComplete func(node *Node, addr *NodeAddress)

func ResolveAddress(node *Node, host string, service string, cb OnResolveAddressComplete) int {
	cnode := (*C.DPS_Node)(node)
	chost := C.CString(host)
	defer C.free(unsafe.Pointer(chost))
	cservice := C.CString(service)
	defer C.free(unsafe.Pointer(cservice))
	handle := reg.register(cb)
	return int(C.resolveAddress(cnode, chost, cservice, C.uintptr_t(handle)))
}

//export goOnResolveAddressComplete
func goOnResolveAddressComplete(cnode *C.DPS_Node, caddr *C.DPS_NodeAddress, handle uintptr) {
	node := (*Node)(cnode)
	addr := (*NodeAddress)(caddr)
	cb, ok := reg.lookup(handle).(OnResolveAddressComplete)
	if ok {
		cb(node, addr)
		reg.unregister(handle)
	}
}

type Publication struct {
	handle  uintptr
	cpub    *C.DPS_Publication
	handler AcknowledgementHandler
}

func PublicationGetUUID(pub *Publication) string {
	return C.GoString(C.DPS_UUIDToString(C.DPS_PublicationGetUUID(pub.cpub)))
}

func PublicationGetSequenceNum(pub *Publication) uint32 {
	return uint32(C.DPS_PublicationGetSequenceNum(pub.cpub))
}

func PublicationGetTopics(pub *Publication) (topics []string) {
	numTopics := int(C.DPS_PublicationGetNumTopics(pub.cpub))
	topics = make([]string, numTopics)
	for i := 0; i < numTopics; i++ {
		topics[i] = C.GoString(C.DPS_PublicationGetTopic(pub.cpub, C.size_t(i)))
	}
	return
}

func PublicationIsAckRequested(pub *Publication) bool {
	if C.DPS_PublicationIsAckRequested(pub.cpub) != 0 {
		return true
	} else {
		return false
	}
}

func PublicationGetSenderKeyId(pub *Publication) (keyId KeyId) {
	ckeyId := C.DPS_PublicationGetSenderKeyId(pub.cpub)
	if ckeyId != nil && ckeyId.id != nil {
		keyId = C.GoBytes(unsafe.Pointer(ckeyId.id), C.int(ckeyId.len))
	}
	return
}

func PublicationGetNode(pub *Publication) *Node {
	return (*Node)(C.DPS_PublicationGetNode(pub.cpub))
}

func CreatePublication(node *Node) (pub *Publication) {
	cnode := (*C.DPS_Node)(node)
	pub = new(Publication)
	pub.handle = reg.register(pub)
	pub.cpub = C.DPS_CreatePublication(cnode)
	C.DPS_SetPublicationData(pub.cpub, unsafe.Pointer(pub.handle))
	return
}

func CopyPublication(pub *Publication) (copy *Publication) {
	copy = new(Publication)
	copy.handle = reg.register(copy)
	copy.cpub = C.DPS_CopyPublication(pub.cpub)
	C.DPS_SetPublicationData(copy.cpub, unsafe.Pointer(copy.handle))
	return
}

type AcknowledgementHandler func(pub *Publication, payload []byte)

func InitPublication(pub *Publication, topics []string, noWildCard bool, keyId KeyId, handler AcknowledgementHandler) int {
	cnumTopics := C.size_t(len(topics))
	ctopics := C.makeTopics(cnumTopics)
	defer C.freeTopics(ctopics, cnumTopics)
	for i, t := range topics {
		C.setTopic(ctopics, C.CString(t), C.size_t(i))
	}
	cnoWildCard := C.int(0)
	if noWildCard {
		cnoWildCard = C.int(1)
	}
	var ckeyId *C.DPS_KeyId = nil
	if keyId != nil {
		ckeyId = &C.DPS_KeyId{(*C.uint8_t)(&keyId[0]), C.size_t(len(keyId))}
	}
	pub.handler = handler
	return int(C.initPublication(pub.cpub, ctopics, cnumTopics, cnoWildCard, ckeyId))
}

//export goAcknowledgementHandler
func goAcknowledgementHandler(cpub *C.DPS_Publication, cpayload *C.uint8_t, clen C.size_t) {
	var payload []byte
	if cpayload != nil {
		payload = (*[1 << 30]byte)(unsafe.Pointer(cpayload))[:clen:clen]
	}
	pub, ok := reg.lookup(uintptr(C.DPS_GetPublicationData(cpub))).(*Publication)
	if ok {
		pub.handler(pub, payload)
	}
}

func PublicationAddSubId(pub *Publication, keyId KeyId) int {
	var ckeyId *C.DPS_KeyId
	if keyId != nil {
		ckeyId = makeKeyId(keyId)
		if ckeyId == nil {
			return ERR_RESOURCES
		}
		defer C.free(unsafe.Pointer(ckeyId))
	}
	return int(C.DPS_PublicationAddSubId(pub.cpub, ckeyId))
}

func PublicationRemoveSubId(pub *Publication, keyId KeyId) {
	var ckeyId *C.DPS_KeyId
	if keyId != nil {
		ckeyId = makeKeyId(keyId)
	}
	if ckeyId != nil {
		defer C.free(unsafe.Pointer(ckeyId))
		C.DPS_PublicationRemoveSubId(pub.cpub, ckeyId)
	}
}

func Publish(pub *Publication, payload []byte, ttl int16) int {
	var cpayload *C.uint8_t = nil
	var clen C.size_t = 0
	if payload != nil {
		cpayload = (*C.uint8_t)(&payload[0])
		clen = C.size_t(len(payload))
	}
	cttl := C.int16_t(ttl)
	return int(C.DPS_Publish(pub.cpub, cpayload, clen, cttl))
}

//export goPublishBufsComplete
func goPublishBufsComplete(cpub *C.DPS_Publication, handle uintptr) {
	reg.unregister(handle)
}
func PublishBufs(pub *Publication, bufs [][]byte, ttl int16) int {
	handle := reg.register(bufs)
	cbufs := C.makeBuffers(C.size_t(len(bufs)))
	defer C.free(unsafe.Pointer(cbufs))
	cbuf := (*[1<<30]C.DPS_Buffer)(unsafe.Pointer(cbufs))
	for i := 0; i < len(bufs); i++ {
		cbuf[i].base = (*C.uint8_t)(&bufs[i][0])
		cbuf[i].len = C.size_t(len(bufs[i]))
	}
	cnumBufs := C.size_t(len(bufs))
	cttl := C.int16_t(ttl)
	return int(C.publishBufs(pub.cpub, cbufs, cnumBufs, cttl, C.uintptr_t(handle)))
}

func DestroyPublication(pub *Publication) (ret int) {
	ret = int(C.DPS_DestroyPublication(pub.cpub))
	if ret == OK {
		reg.unregister(pub.handle)
	}
	return
}

func AckPublication(pub *Publication, payload []byte) int {
	var cpayload *C.uint8_t = nil
	var clen C.size_t = 0
	if payload != nil {
		cpayload = (*C.uint8_t)(&payload[0])
		clen = C.size_t(len(payload))
	}
	return int(C.DPS_AckPublication(pub.cpub, cpayload, clen))
}

//export goAckPublicationBufsComplete
func goAckPublicationBufsComplete(cpub *C.DPS_Publication, handle uintptr) {
	reg.unregister(handle)
}
func AckPublicationBufs(pub *Publication, bufs [][]byte) int {
	handle := reg.register(bufs)
	cbufs := C.makeBuffers(C.size_t(len(bufs)))
	defer C.free(unsafe.Pointer(cbufs))
	cbuf := (*[1<<30]C.DPS_Buffer)(unsafe.Pointer(cbufs))
	for i := 0; i < len(bufs); i++ {
		cbuf[i].base = (*C.uint8_t)(&bufs[i][0])
		cbuf[i].len = C.size_t(len(bufs[i]))
	}
	cnumBufs := C.size_t(len(bufs))
	return int(C.ackPublicationBufs(pub.cpub, cbufs, cnumBufs, C.uintptr_t(handle)))
}

func AckGetSenderKeyId(pub *Publication) (keyId KeyId) {
	ckeyId := C.DPS_AckGetSenderKeyId(pub.cpub)
	if ckeyId != nil && ckeyId.id != nil {
		keyId = C.GoBytes(unsafe.Pointer(ckeyId.id), C.int(ckeyId.len))
	}
	return
}

type Subscription struct {
	handle  uintptr
	csub    *C.DPS_Subscription
	handler PublicationHandler
}

func SubscriptionGetTopics(sub *Subscription) (topics []string) {
	numTopics := int(C.DPS_SubscriptionGetNumTopics(sub.csub))
	topics = make([]string, numTopics)
	for i := 0; i < numTopics; i++ {
		topics[i] = C.GoString(C.DPS_SubscriptionGetTopic(sub.csub, C.size_t(i)))
	}
	return
}

func CreateSubscription(node *Node, topics []string) (sub *Subscription) {
	cnode := (*C.DPS_Node)(node)
	cnumTopics := C.size_t(len(topics))
	ctopics := C.makeTopics(cnumTopics)
	defer C.freeTopics(ctopics, cnumTopics)
	for i, t := range topics {
		C.setTopic(ctopics, C.CString(t), C.size_t(i))
	}
	sub = new(Subscription)
	sub.handle = reg.register(sub)
	sub.csub = C.DPS_CreateSubscription(cnode, ctopics, cnumTopics)
	C.DPS_SetSubscriptionData(sub.csub, unsafe.Pointer(sub.handle))
	return
}

func SubscriptionGetNode(sub *Subscription) *Node {
	return (*Node)(C.DPS_SubscriptionGetNode(sub.csub))
}

type PublicationHandler func(sub *Subscription, pub *Publication, payload []byte)

func Subscribe(sub *Subscription, handler PublicationHandler) int {
	sub.handler = handler
	return int(C.subscribe(sub.csub))
}

//export goPublicationHandler
func goPublicationHandler(csub *C.DPS_Subscription, cpub *C.DPS_Publication, cpayload *C.uint8_t, clen C.size_t) {
	pub := Publication{0, cpub, nil}
	var payload []byte
	if cpayload != nil {
		payload = (*[1 << 30]byte)(unsafe.Pointer(cpayload))[:clen:clen]
	}
	sub, ok := reg.lookup(uintptr(C.DPS_GetSubscriptionData(csub))).(*Subscription)
	if ok {
		sub.handler(sub, &pub, payload)
	}
}

func DestroySubscription(sub *Subscription) (ret int) {
	ret = int(C.DPS_DestroySubscription(sub.csub))
	if ret == OK {
		reg.unregister(sub.handle)
	}
	return
}

const (
	OK                  int = 0
	ERR_OK                  = 0
	ERR_FAILURE             = 1
	ERR_NULL                = 2
	ERR_ARGS                = 3
	ERR_RESOURCES           = 4
	ERR_READ                = 5
	ERR_WRITE               = 6
	ERR_TIMEOUT             = 7
	ERR_EOD                 = 8
	ERR_OVERFLOW            = 9
	ERR_NETWORK             = 10
	ERR_INVALID             = 11
	ERR_BUSY                = 12
	ERR_EXISTS              = 13
	ERR_MISSING             = 14
	ERR_STALE               = 15
	ERR_NO_ROUTE            = 16
	ERR_NOT_STARTED         = 17
	ERR_NOT_INITIALIZED     = 18
	ERR_EXPIRED             = 19
	ERR_UNRESOLVED          = 20
	ERR_NODE_DESTROYED      = 21
	ERR_EOF                 = 22
	ERR_NOT_IMPLEMENTED     = 23
	ERR_SECURITY            = 24
	ERR_NOT_ENCRYPTED       = 25
	ERR_STOPPING            = 26
	ERR_RANGE               = 27
	ERR_LOST_PRECISION      = 28
)

func ErrTxt(err int) string {
	return C.GoString(C.DPS_ErrTxt(C.DPS_Status(err)))
}

func JSON2CBOR(json string) (cbor []byte, err int) {
	cjson := C.CString(json)
	defer C.free(unsafe.Pointer(cjson))
	err = ERR_OVERFLOW
	var outLen C.size_t
	for n := 4096; err == ERR_OVERFLOW; n = n * 2 {
		cbor = make([]byte, n)
		err = int(C.DPS_JSON2CBOR(cjson, (*C.uint8_t)(&cbor[0]), C.size_t(len(cbor)), &outLen))
	}
	cbor = cbor[:outLen]
	return
}

func CBOR2JSON(cbor []byte, pretty bool) (json string, err int) {
	err = ERR_OVERFLOW
	var cpretty C.int = 0
	if pretty {
		cpretty = 1
	}
	var buf []byte
	for n := 4096; err == ERR_OVERFLOW; n = n * 2 {
		buf = make([]byte, n)
		err = int(C.DPS_CBOR2JSON((*C.uint8_t)(&cbor[0]), C.size_t(len(cbor)),
			(*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), cpretty))
	}
	json = string(buf)
	return
}

func LinkTo(node *Node, addrText string, addr *NodeAddress) int {
	cnode := (*C.DPS_Node)(node)
	var caddrText *C.char
	if len(addrText) > 0 {
		caddrText = C.CString(addrText)
	}
	defer C.free(unsafe.Pointer(caddrText))
	caddr := (*C.DPS_NodeAddress)(addr)
	return int(C.DPS_LinkTo(cnode, caddrText, caddr))
}

func UnlinkFrom(node *Node, addr *NodeAddress) int {
	cnode := (*C.DPS_Node)(node)
	caddr := (*C.DPS_NodeAddress)(addr)
	return int(C.DPS_UnlinkFrom(cnode, caddr))
}

type UUID C.DPS_UUID

func InitUUID() int {
	return int(C.DPS_InitUUID())
}

func GenerateUUID() (uuid *UUID) {
	cuuid := (*C.DPS_UUID)(uuid)
	C.DPS_GenerateUUID(cuuid)
	return
}

func UUIDToString(uuid *UUID) string {
	cuuid := (*C.DPS_UUID)(uuid)
	return C.GoString(C.DPS_UUIDToString(cuuid))
}

func UUIDCompare(a *UUID, b *UUID) int {
	ca := (*C.DPS_UUID)(a)
	cb := (*C.DPS_UUID)(b)
	return int(C.DPS_UUIDCompare(ca, cb))
}
