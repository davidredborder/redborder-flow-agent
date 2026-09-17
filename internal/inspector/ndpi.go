package inspector

// NDPIFlow represents an opaque pointer or handle to a protocol detection flow.
type NDPIFlow interface{}

// NDPIClassifier provides deep packet inspection protocol classification.
// If compiled with CGO and libndpi (-tags ndpi), it invokes nDPI;
// otherwise it falls back to native protocol heuristics.
type NDPIClassifier interface {
	ProcessPacket(data []byte, ts int64) (protoName string, protoID uint16, category string)
	AllocFlow() NDPIFlow
	ProcessFlowPacket(flow NDPIFlow, ipData []byte, ts int64) (protoName string, protoID uint16, category string)
	FreeFlow(flow NDPIFlow)
	Close()
}

