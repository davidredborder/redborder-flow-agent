//go:build ndpi && cgo

package inspector

/*
#cgo CFLAGS: -I/usr/include/libndpi -I/usr/local/include/libndpi -I/usr/include/ndpi -I/usr/local/include/ndpi
#cgo LDFLAGS: -lndpi -lm -lpthread
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if __has_include(<libndpi/ndpi_api.h>)
#include <libndpi/ndpi_api.h>
#elif __has_include(<ndpi/ndpi_api.h>)
#include <ndpi/ndpi_api.h>
#else
#include <ndpi_api.h>
#endif

static const char* get_ndpi_version_string() {
#ifdef NDPI_GIT_RELEASE
    return NDPI_GIT_RELEASE;
#elif defined(LIBNDPI_VERSION_STR)
    return LIBNDPI_VERSION_STR;
#elif defined(NDPI_API_VERSION)
    return ndpi_revision();
#else
    return "3.x/4.x/5.x";
#endif
}

typedef struct {
    struct ndpi_detection_module_struct *ndpi_mod;
} ndpi_wrapper_t;

static void free_ndpi_wrapper(ndpi_wrapper_t *w) {
    if (w) {
        if (w->ndpi_mod) {
            ndpi_exit_detection_module(w->ndpi_mod);
        }
        free(w);
    }
}

#if defined(NDPI_MAJOR) && NDPI_MAJOR >= 4

static ndpi_wrapper_t* init_ndpi_wrapper() {
    ndpi_wrapper_t *w = (ndpi_wrapper_t*)calloc(1, sizeof(ndpi_wrapper_t));
    if (!w) return NULL;
#if defined(NDPI_MAJOR) && NDPI_MAJOR >= 6
    w->ndpi_mod = ndpi_init_detection_module(NULL, NDPI_LICENSE_NOT_FOR_PROFIT_LGPL);
#elif defined(NDPI_MAJOR) && NDPI_MAJOR == 5
    w->ndpi_mod = ndpi_init_detection_module(NULL);
#elif (defined(NDPI_MAJOR) && NDPI_MAJOR == 4 && defined(NDPI_MINOR) && NDPI_MINOR >= 4)
    w->ndpi_mod = ndpi_init_detection_module(NULL);
#elif defined(NDPI_LICENSE_NOT_FOR_PROFIT_LGPL)
    w->ndpi_mod = ndpi_init_detection_module(NULL, NDPI_LICENSE_NOT_FOR_PROFIT_LGPL);
#else
    w->ndpi_mod = ndpi_init_detection_module(ndpi_no_prefs);
#endif
    if (!w->ndpi_mod) {
        free(w);
        return NULL;
    }
#if defined(NDPI_MAJOR) && NDPI_MAJOR < 5
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(w->ndpi_mod, &all);
#endif
    ndpi_finalize_initialization(w->ndpi_mod);
    return w;
}

static const char* ndpi_classify_flow_pkt(ndpi_wrapper_t *w, struct ndpi_flow_struct *flow, const uint8_t *data, uint16_t len, uint64_t ts, uint16_t *proto_id_out, const char **category_out) {
    if (!w || !w->ndpi_mod || !flow || !data || len == 0) {
        if (proto_id_out) *proto_id_out = 0;
        if (category_out) *category_out = "";
        return "";
    }
    
    ndpi_protocol proto = ndpi_detection_process_packet(w->ndpi_mod, flow, data, len, ts, NULL);
    uint16_t pid = proto.proto.app_protocol;
    if (pid == 0) {
        pid = proto.proto.master_protocol;
    }
    if (proto_id_out) *proto_id_out = pid;

    const char *name = ndpi_get_proto_name(w->ndpi_mod, proto.proto.app_protocol);
    if (!name || strcmp(name, "Unknown") == 0) {
        name = ndpi_get_proto_name(w->ndpi_mod, proto.proto.master_protocol);
    }
    if (category_out) {
        *category_out = ndpi_category_get_name(w->ndpi_mod, proto.category);
        if (!*category_out) *category_out = "";
    }
    return name ? name : "";
}

#else // nDPI 3.x

static ndpi_wrapper_t* init_ndpi_wrapper() {
    ndpi_wrapper_t *w = (ndpi_wrapper_t*)calloc(1, sizeof(ndpi_wrapper_t));
    if (!w) return NULL;
    w->ndpi_mod = ndpi_init_detection_module(ndpi_no_prefs);
    if (!w->ndpi_mod) {
        free(w);
        return NULL;
    }
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(w->ndpi_mod, &all);
    ndpi_finalize_initalization(w->ndpi_mod);
    return w;
}

static const char* ndpi_classify_flow_pkt(ndpi_wrapper_t *w, struct ndpi_flow_struct *flow, const uint8_t *data, uint16_t len, uint64_t ts, uint16_t *proto_id_out, const char **category_out) {
    if (!w || !w->ndpi_mod || !flow || !data || len == 0) {
        if (proto_id_out) *proto_id_out = 0;
        if (category_out) *category_out = "";
        return "";
    }
    
    ndpi_protocol proto = ndpi_detection_process_packet(w->ndpi_mod, flow, data, len, ts, NULL, NULL);
    uint16_t pid = proto.app_protocol;
    if (pid == 0) {
        pid = proto.master_protocol;
    }
    if (proto_id_out) *proto_id_out = pid;

    const char *name = ndpi_get_proto_name(w->ndpi_mod, proto.app_protocol);
    if (!name || strcmp(name, "Unknown") == 0) {
        name = ndpi_get_proto_name(w->ndpi_mod, proto.master_protocol);
    }
    if (category_out) {
        *category_out = ndpi_category_get_name(w->ndpi_mod, proto.category);
        if (!*category_out) *category_out = "";
    }
    return name ? name : "";
}

#endif

static struct ndpi_flow_struct* ndpi_alloc_flow_struct() {
    return (struct ndpi_flow_struct*)calloc(1, sizeof(struct ndpi_flow_struct));
}

static void ndpi_free_flow_struct(struct ndpi_flow_struct *flow) {
    if (flow) {
        ndpi_free_flow(flow);
    }
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// NDPIStatus returns runtime compilation status and supported versions for nDPI.
func NDPIStatus() (enabled bool, details string) {
	ver := C.GoString(C.get_ndpi_version_string())
	return true, fmt.Sprintf("Enabled (linked with libndpi %s, compatible with nDPI 4.x/5.x/6.x)", ver)
}

type cgoNDPI struct {
	wrapper *C.ndpi_wrapper_t
}

// NewNDPIClassifier initializes nDPI detection module via CGO.
func NewNDPIClassifier() (NDPIClassifier, error) {
	w := C.init_ndpi_wrapper()
	if w == nil {
		return nil, fmt.Errorf("failed to initialize nDPI C module")
	}
	return &cgoNDPI{wrapper: w}, nil
}

func (c *cgoNDPI) AllocFlow() NDPIFlow {
	flow := C.ndpi_alloc_flow_struct()
	if flow == nil {
		return nil
	}
	return flow
}

func (c *cgoNDPI) ProcessFlowPacket(flow NDPIFlow, ipData []byte, ts int64) (string, uint16, string) {
	if len(ipData) == 0 || c.wrapper == nil || flow == nil {
		return "", 0, ""
	}
	cFlow, ok := flow.(*C.struct_ndpi_flow_struct)
	if !ok || cFlow == nil {
		return "", 0, ""
	}

	var cCategory *C.char
	var cProtoID C.uint16_t
	ptr := (*C.uint8_t)(unsafe.Pointer(&ipData[0]))
	cName := C.ndpi_classify_flow_pkt(c.wrapper, cFlow, ptr, C.uint16_t(len(ipData)), C.uint64_t(ts), &cProtoID, &cCategory)
	protoName := C.GoString(cName)
	if protoName == "Unknown" {
		protoName = ""
	}
	category := ""
	if cCategory != nil {
		category = C.GoString(cCategory)
	}
	return protoName, uint16(cProtoID), category
}

func (c *cgoNDPI) FreeFlow(flow NDPIFlow) {
	if flow == nil {
		return
	}
	if cFlow, ok := flow.(*C.struct_ndpi_flow_struct); ok && cFlow != nil {
		C.ndpi_free_flow_struct(cFlow)
	}
}

func (c *cgoNDPI) ProcessPacket(data []byte, ts int64) (string, uint16, string) {
	if len(data) == 0 || c.wrapper == nil {
		return "", 0, ""
	}
	f := c.AllocFlow()
	if f == nil {
		return "", 0, ""
	}
	defer c.FreeFlow(f)
	return c.ProcessFlowPacket(f, data, ts)
}

func (c *cgoNDPI) Close() {
	if c.wrapper != nil {
		C.free_ndpi_wrapper(c.wrapper)
		c.wrapper = nil
	}
}
