package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// htons converts uint16 from host to network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | (i>>8)&0x00ff
}

// InterfaceWorker captures packets from a single network interface.
type InterfaceWorker struct {
	ifaceName   string
	ifIndex     uint32
	promisc     bool
	snaplen     int
	workers     int
	outChan     chan *ParsedPacket
	logger      *slog.Logger
	rawSocks    []int
	cancelFunc  context.CancelFunc
	wg          sync.WaitGroup
}

// NewInterfaceWorker creates a capture worker for a specified interface.
func NewInterfaceWorker(ifaceName string, promisc bool, snaplen, workers int, outChan chan *ParsedPacket, logger *slog.Logger) (*InterfaceWorker, error) {
	if snaplen <= 0 {
		snaplen = 1518
	}
	if workers <= 0 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}

	var ifIndex uint32
	if ifaceName != "" && ifaceName != "any" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
		}
		ifIndex = uint32(iface.Index)
	}

	return &InterfaceWorker{
		ifaceName: ifaceName,
		ifIndex:   ifIndex,
		promisc:   promisc,
		snaplen:   snaplen,
		workers:   workers,
		outChan:   outChan,
		logger:    logger,
		rawSocks:  make([]int, 0, workers),
	}, nil
}

// Start launches capture goroutines.
func (w *InterfaceWorker) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	w.cancelFunc = cancel

	proto := int(htons(unix.ETH_P_ALL))

	for i := 0; i < w.workers; i++ {
		sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, proto)
		if err != nil {
			w.Close()
			return fmt.Errorf("failed to open raw AF_PACKET socket for %s (requires root or CAP_NET_RAW): %w", w.ifaceName, err)
		}
		w.rawSocks = append(w.rawSocks, sock)

		if w.ifIndex > 0 {
			sll := unix.SockaddrLinklayer{
				Protocol: uint16(proto),
				Ifindex:  int(w.ifIndex),
			}
			if err := unix.Bind(sock, &sll); err != nil {
				w.Close()
				return fmt.Errorf("failed to bind socket to %s: %w", w.ifaceName, err)
			}

			if w.promisc {
				mreq := unix.PacketMreq{
					Ifindex: int32(w.ifIndex),
					Type:    unix.PACKET_MR_PROMISC,
				}
				_ = unix.SetsockoptPacketMreq(sock, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
			}
		}

		// Set 500ms read timeout so Recvfrom does not block indefinitely when an interface has no traffic
		tv := unix.Timeval{Sec: 0, Usec: 500000}
		_ = unix.SetsockoptTimeval(sock, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

		// Enable PACKET_AUXDATA so Linux kernel provides hardware-stripped VLAN tags via ancillary cmsg
		_ = unix.SetsockoptInt(sock, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1)

		// When multiple workers capture on the same interface, enable PACKET_FANOUT
		// so the Linux kernel distributes flows across sockets instead of duplicating packets to each socket.
		if w.workers > 1 {
			fanoutID := (int(w.ifIndex) + 100) & 0xFFFF
			if fanoutID == 0 {
				fanoutID = 101
			}
			fanoutArg := fanoutID | (unix.PACKET_FANOUT_HASH << 16) | (unix.PACKET_FANOUT_FLAG_DEFRAG << 16)
			if err := unix.SetsockoptInt(sock, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg); err != nil {
				// Fallback without DEFRAG flag if kernel doesn't support it
				if err2 := unix.SetsockoptInt(sock, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutID|(unix.PACKET_FANOUT_HASH<<16)); err2 != nil {
					w.logger.Warn("Failed to set PACKET_FANOUT, packets may be duplicated across workers", "err", err2)
				}
			}
		}

		w.wg.Add(1)
		go w.captureLoop(ctx, sock, i)
	}

	w.logger.Info("AF_PACKET capture running", "interface", w.ifaceName, "workers", w.workers)
	return nil
}

func (w *InterfaceWorker) captureLoop(ctx context.Context, sock int, workerID int) {
	defer w.wg.Done()

	buf := make([]byte, 65536)
	oob := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, 0)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EINTR {
					continue
				}
				// Socket closed or errored
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}

			if n <= 0 {
				continue
			}

			// Check for hardware/kernel stripped VLAN tag in control messages (PACKET_AUXDATA)
			var auxVlan uint16
			if oobn > 0 {
				cmsgs, cmsgErr := unix.ParseSocketControlMessage(oob[:oobn])
				if cmsgErr == nil {
					for _, cmsg := range cmsgs {
						if cmsg.Header.Level == unix.SOL_PACKET && cmsg.Header.Type == unix.PACKET_AUXDATA {
							// struct tpacket_auxdata layout:
							// tp_status (uint32), tp_len (uint32), tp_snaplen (uint32), tp_mac (uint16), tp_net (uint16), tp_vlan_tci (uint16)
							if len(cmsg.Data) >= 18 {
								tpStatus := binary.LittleEndian.Uint32(cmsg.Data[0:4])
								if tpStatus&16 != 0 { // TP_STATUS_VLAN_VALID
									tci := binary.LittleEndian.Uint16(cmsg.Data[16:18])
									auxVlan = tci & 0x0FFF
								}
							}
						}
					}
				}
			}

			pktData := make([]byte, n)
			copy(pktData, buf[:n])

			now := time.Now()
			wireLen := n
			parsed, err := FastDecode(pktData, now, n, wireLen, w.ifaceName, w.ifIndex)
			if err != nil {
				continue
			}

			if parsed.VLANID == 0 && auxVlan > 0 {
				parsed.VLANID = auxVlan
			}

			select {
			case w.outChan <- parsed:
			default:
				// Buffer full; avoid blocking capture worker
			}
		}
	}
}

// Close gracefully terminates all sockets for this interface.
func (w *InterfaceWorker) Close() {
	if w.cancelFunc != nil {
		w.cancelFunc()
	}
	for _, sock := range w.rawSocks {
		if sock > 0 {
			_ = unix.Close(sock)
		}
	}
	w.wg.Wait()
	w.rawSocks = nil
}
