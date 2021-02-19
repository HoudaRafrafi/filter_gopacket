package main

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/pcapgo"
    "fmt"
    "log"
    "strings"
    "time"
    "os"
)

var (

    device      string = "wlp0s20f3"
    snapshotLen int32  = 65535
    promiscuous bool   = false
    err         error
    timeout     time.Duration = -1 * time.Second
    handle      *pcap.Handle
    packetCount int = 0
)

func main() {

    // Open output pcap file and write header 
	f, _ := os.Create("test.pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	defer f.Close()

    // Open device
    handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil {
        log.Fatal(err) 
    }
    defer handle.Close()

    var filter string ="src host 192.168.1.2 and port 443"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        printPacketInfo(packet)
        w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		packetCount++
		
		// Only capture 100 and then stop
		if packetCount > 100 {
			break
		}
    }
}

func printPacketInfo(packet gopacket.Packet) {
   
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {

        fmt.Println("IPv4 layer detected.")
        ip, _ := ipLayer.(*layers.IPv4)
        fmt.Println("Source address", ip.SrcIP)
        fmt.Println("Destination address", ip.DstIP)
        fmt.Println("Protocol: ", ip.Protocol)
        fmt.Println()
        
    }

    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {

        fmt.Println("TCP layer detected.")
        tcp, _ := tcpLayer.(*layers.TCP)
        fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
        fmt.Println()

    }

    // When iterating through packet.Layers() above,
    // if it lists Payload layer then that is the same as
    // this applicationLayer. applicationLayer contains the payload
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {

        fmt.Println("Application layer/Payload found.")
        fmt.Printf("%s\n", applicationLayer.Payload())

        // Search for a string inside the payload
        if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
            fmt.Println("HTTP found!")
        }
    }

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }
}