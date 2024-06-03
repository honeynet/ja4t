package ja4t

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// JA4T is a struct to hold the JA4T fingerprint
type JA4T struct {
	WindowSize         uint16
	Options            []uint8
	MaximumSegmentSize uint16
	WindowScale        uint8
}

func (ja4 *JA4T) String() string {
	str := fmt.Sprintf("JA4T=%v_", ja4.WindowSize)
	options := make([]string, len(ja4.Options))
	for i, o := range ja4.Options {
		options[i] = fmt.Sprintf("%v", o)
	}
	str += strings.Join(options, "-") + "_"
	return str + fmt.Sprintf("%v_%v", ja4.MaximumSegmentSize, ja4.WindowScale)
}

func ParseFile(fileName string) ([]JA4T, error) {
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	packetJAs := []JA4T{}
	for pkt := range packets {
		jas, err := ParseLayers(pkt.Layers())
		if err != nil {
			return nil, err
		}
		packetJAs = append(packetJAs, jas...)
	}
	return packetJAs, nil
}

func ParseLayers(lrs []gopacket.Layer) ([]JA4T, error) {
	jas := []JA4T{}
	for _, layer := range lrs {
		switch layer.LayerType() {
		case layers.LayerTypeTCP:
			tcp, ok := layer.(*layers.TCP)
			if !ok {
				continue
			}
			ja, err := ParseTCP(tcp)
			if err != nil {
				return nil, err
			}
			// TODO: this might be too rough
			if len(ja.Options) > 0 && ja.WindowScale > 0 {
				jas = append(jas, ja)
			}
		}
	}
	return jas, nil
}

func ParseTCP(tcp *layers.TCP) (JA4T, error) {
	ja := JA4T{
		WindowSize: tcp.Window,
	}
	// TODO: is this always true?
	if len(tcp.Options) == 0 {
		return ja, nil
	}
	for _, o := range tcp.Options {
		ja.Options = append(ja.Options, uint8(o.OptionType))
		switch o.OptionType {
		case layers.TCPOptionKindWindowScale:
			ja.WindowScale = o.OptionData[0]
		case layers.TCPOptionKindMSS:
			ja.MaximumSegmentSize = binary.BigEndian.Uint16(o.OptionData)
		}
	}
	return ja, nil
}
