/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"encoding/binary"
	"errors"
	"os"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/wintun"
)

const (
	packetSizeMax           uint32 = 0xeffc   // Maximum packet size: 4 + packetSizeMax == 0xf000
	packetExchangeMax       uint32 = 256      // Number of packets that may be written at a time
	packetExchangeAlignment uint32 = 16       // Number of bytes packets are aligned to in exchange buffers
	packetExchangeSizeRd    uint32 = 0x100000 // Read exchange buffer size (defaults to 1MiB)
	packetExchangeSizeWr    uint32 = 0x10000  // Write exchange buffer size (defaults to 64kiB)
)

const (
	signalClose = iota
	signalDataAvail

	signalMax
)

type nativeTun struct {
	wt          *wintun.Wintun
	tunName     string
	signalName  *uint16
	tunFile     *os.File
	wrBuff      []byte
	rdBuff      []byte
	signals     [signalMax]windows.Handle
	wrPacketNum uint32
	rdOffset    uint32
	events      chan TUNEvent
	errors      chan error
}

func packetAlign(size uint32) uint32 {
	return (size + (packetExchangeAlignment - 1)) &^ (packetExchangeAlignment - 1)
}

func CreateTUN(ifname string) (TUNDevice, error) {
	// Does an interface with this name already exist?
	wt, err := wintun.GetInterface(ifname, 0)
	if wt == nil {
		// Interface does not exist or an error occured. Create one.
		wt, _, err = wintun.CreateInterface("WireGuard Tunnel Adapter", 0)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		// Foreign interface with the same name found.
		// We could create a Wintun interface under a temporary name. But, should our
		// proces die without deleting this interface first, the interface would remain
		// orphaned.
		return nil, err
	}

	err = wt.SetInterfaceName(ifname)
	if err != nil {
		wt.DeleteInterface(0)
		return nil, err
	}

	err = wt.FlushInterface()
	if err != nil {
		wt.DeleteInterface(0)
		return nil, err
	}

	signalNameUTF16, err := windows.UTF16PtrFromString(wt.SignalEventName())
	if err != nil {
		wt.DeleteInterface(0)
		return nil, err
	}

	// Create instance.
	tun := &nativeTun{
		wt:         wt,
		tunName:    wt.DataFileName(),
		signalName: signalNameUTF16,
		wrBuff:     make([]byte, 0, packetExchangeSizeWr),
		rdBuff:     make([]byte, 0, packetExchangeSizeRd),
		events:     make(chan TUNEvent, 10),
		errors:     make(chan error, 1),
	}

	// Create close event.
	tun.signals[signalClose], err = windows.CreateEvent(nil, 1 /*TRUE*/, 0 /*FALSE*/, nil)
	if err != nil {
		wt.DeleteInterface(0)
		return nil, err
	}

	return tun, nil
}

func (tun *nativeTun) openTUN() error {
	for {
		// Open interface data pipe.
		// Data pipe must be opened first, as the interface data available event is created when somebody actually connects to the data pipe.
		file, err := os.OpenFile(tun.tunName, os.O_RDWR|os.O_SYNC, 0600)
		if err != nil {
			// After examining possible error conditions, many arose that were only temporary: windows.ERROR_FILE_NOT_FOUND, "read <filename> closed", etc.
			// To simplify, we will enter a retry-loop on _any_ error until session is closed by user.
			switch evt, e := windows.WaitForSingleObject(tun.signals[signalClose], 1000); evt {
			case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
				return errors.New("TUN closed")
			case windows.WAIT_TIMEOUT:
				continue
			default:
				return errors.New("Unexpected result from WaitForSingleObject: " + e.Error())
			}
		}

		// Open interface data available event.
		event, err := windows.OpenEvent(windows.SYNCHRONIZE, false, tun.signalName)
		if err != nil {
			file.Close()
			return errors.New("Opening interface data ready event failed: " + err.Error())
		}

		tun.tunFile = file
		tun.signals[signalDataAvail] = event

		return nil
	}
}

func (tun *nativeTun) closeTUN() (err error) {
	if tun.signals[signalDataAvail] != 0 {
		// Close interface data ready event.
		e := windows.CloseHandle(tun.signals[signalDataAvail])
		if err != nil {
			err = e
		}

		tun.signals[signalDataAvail] = 0
	}

	if tun.tunFile != nil {
		// Close interface data pipe.
		e := tun.tunFile.Close()
		if err != nil {
			err = e
		}

		tun.tunFile = nil
	}

	return
}

func (tun *nativeTun) Name() (string, error) {
	return tun.wt.GetInterfaceName()
}

func (tun *nativeTun) File() *os.File {
	return nil
}

func (tun *nativeTun) Events() chan TUNEvent {
	return tun.events
}

func (tun *nativeTun) Close() error {
	windows.SetEvent(tun.signals[signalClose])
	err := windows.CloseHandle(tun.signals[signalClose])

	e := tun.closeTUN()
	if err == nil {
		err = e
	}

	if tun.events != nil {
		close(tun.events)
	}

	_, _, e = tun.wt.DeleteInterface(0)
	if err == nil {
		err = e
	}

	return err
}

func (tun *nativeTun) MTU() (int, error) {
	return 1500, nil
}

func (tun *nativeTun) Read(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
	}

	for {
		if tun.rdOffset+4 <= uint32(len(tun.rdBuff)) {
			// Get packet from the exchange buffer.
			size := binary.LittleEndian.Uint32(tun.rdBuff[tun.rdOffset:])
			offsetEnd := tun.rdOffset + packetAlign(4+size)
			if size > packetSizeMax || offsetEnd > uint32(len(tun.rdBuff)) {
				// Invalid packet size.
				tun.rdBuff = tun.rdBuff[:0]
				continue
			}

			// Copy data.
			packet := tun.rdBuff[tun.rdOffset:offsetEnd]
			copy(buff[offset:], packet[4:][:size])
			tun.rdOffset = offsetEnd
			return int(size), nil
		}

		if tun.signals[signalDataAvail] == 0 {
			// Data pipe and interface data available event are not open (yet).
			err := tun.openTUN()
			if err != nil {
				return 0, err
			}
		}

		// Wait for user close or interface data.
		r, err := windows.WaitForMultipleObjects(tun.signals[:], false, windows.INFINITE)
		if err != nil {
			return 0, errors.New("Waiting for data failed: " + err.Error())
		}
		switch r {
		case windows.WAIT_OBJECT_0 + signalClose, windows.WAIT_ABANDONED + signalClose:
			return 0, errors.New("TUN closed")
		case windows.WAIT_OBJECT_0 + signalDataAvail:
			// Data is available.
		case windows.WAIT_ABANDONED + signalDataAvail:
			// TUN stopped. Reopen it.
			tun.closeTUN()
			continue
		case windows.WAIT_TIMEOUT:
			// Congratulations, we reached infinity. Let's do it again! :)
			continue
		default:
			return 0, errors.New("unexpected result from WaitForMultipleObjects")
		}

		// Fill queue.
		n, err := tun.tunFile.Read(tun.rdBuff[:cap(tun.rdBuff)])
		if err != nil {
			// TUN interface stopped, failed, etc. Retry.
			tun.rdBuff = tun.rdBuff[:0]
			tun.closeTUN()
			continue
		}
		tun.rdOffset = 0
		tun.rdBuff = tun.rdBuff[:n]
	}
}

// Note: flush() and putTunPacket() assume the caller comes only from a single thread; there's no locking.

func (tun *nativeTun) flush() error {
	// Flush write buffer.
	_, err := tun.tunFile.Write(tun.wrBuff)
	tun.wrPacketNum = 0
	tun.wrBuff = tun.wrBuff[:0]
	if err != nil {
		return err
	}

	return nil
}

func (tun *nativeTun) putTunPacket(buff []byte) error {
	size := uint32(len(buff))
	if size == 0 {
		return errors.New("Empty packet")
	}
	if size > packetSizeMax {
		return errors.New("Packet too big")
	}
	offsetStart := uint32(len(tun.wrBuff))
	offsetEnd := offsetStart + packetAlign(4+size)
	if tun.wrPacketNum >= packetExchangeMax || offsetEnd > uint32(cap(tun.wrBuff)) {
		// Exchange buffer is full -> flush first.
		err := tun.flush()
		if err != nil {
			return err
		}
	}

	// Put packet to the exchange buffer.
	tun.wrBuff = tun.wrBuff[:offsetEnd]
	packet := tun.wrBuff[offsetStart:offsetEnd]
	binary.LittleEndian.PutUint32(packet[0:], size)
	copy(packet[4:], buff)
	tun.wrPacketNum++

	return nil
}

func (tun *nativeTun) Write(buff []byte, offset int) (int, error) {
	err := tun.putTunPacket(buff[offset:])
	if err != nil {
		return 0, err
	}

	// Flush write buffer.
	return len(buff) - offset, tun.flush()
}
