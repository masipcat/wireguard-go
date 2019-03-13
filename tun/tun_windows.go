/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/wintun"
)

const (
	packetExchangeMax       uint32 = 256                              // Number of packets that may be written at a time
	packetExchangeAlignment uint32 = 16                               // Number of bytes packets are aligned to in exchange buffers
	packetSizeMax           uint32 = 0xf000 - packetExchangeAlignment // Maximum packet size
	packetExchangeSize      uint32 = 0x100000                         // Exchange buffer size (defaults to 1MiB)
)

type exchgBufRead struct {
	data   [packetExchangeSize]byte
	offset uint32
	avail  uint32
}

type exchgBufWrite struct {
	data      [packetExchangeSize]byte
	offset    uint32
	packetNum uint32
}

type NativeTun struct {
	wt        *wintun.Wintun
	tunName   string
	tunFile   *os.File
	tunLock   sync.Mutex
	rdBuff    *exchgBufRead
	wrBuff    *exchgBufWrite
	userClose windows.Handle
	events    chan TUNEvent
	errors    chan error
	forcedMtu int
}

func packetAlign(size uint32) uint32 {
	return (size + (packetExchangeAlignment - 1)) &^ (packetExchangeAlignment - 1)
}

//
// CreateTUN creates a Wintun adapter with the given name. Should a Wintun
// adapter with the same name exist, it is reused.
//
func CreateTUN(ifname string) (TUNDevice, error) {
	// Does an interface with this name already exist?
	wt, err := wintun.GetInterface(ifname, 0)
	if wt == nil {
		// Interface does not exist or an error occured. Create one.
		wt, _, err = wintun.CreateInterface("WireGuard Tunnel Adapter", 0)
		if err != nil {
			return nil, errors.New("Creating Wintun adapter failed: " + err.Error())
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
		return nil, errors.New("Setting interface name failed: " + err.Error())
	}

	err = wt.FlushInterface()
	if err != nil {
		wt.DeleteInterface(0)
		return nil, errors.New("Flushing interface failed: " + err.Error())
	}

	// Create instance.
	tun := &NativeTun{
		wt:        wt,
		tunName:   wt.DataFileName(),
		rdBuff:    &exchgBufRead{},
		wrBuff:    &exchgBufWrite{},
		events:    make(chan TUNEvent, 10),
		errors:    make(chan error, 1),
		forcedMtu: 1500,
	}

	// Create close event.
	tun.userClose, err = windows.CreateEvent(nil, 1 /*TRUE*/, 0 /*FALSE*/, nil)
	if err != nil {
		wt.DeleteInterface(0)
		return nil, err
	}

	return tun, nil
}

func (tun *NativeTun) openTUN() error {
	for {
		// Open interface data pipe.
		// Data pipe must be opened first, as the interface data available event is created when somebody actually connects to the data pipe.
		file, err := os.OpenFile(tun.tunName, os.O_RDWR|os.O_SYNC, 0600)
		if err != nil {
			// After examining possible error conditions, many arose that were only temporary: windows.ERROR_FILE_NOT_FOUND, "read <filename> closed", etc.
			// To simplify, we will enter a retry-loop on _any_ error until session is closed by user.
			switch evt, e := windows.WaitForSingleObject(tun.userClose, 1000); evt {
			case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
				return errors.New("TUN closed")
			case windows.WAIT_TIMEOUT:
				continue
			default:
				return errors.New("Unexpected result from WaitForSingleObject: " + e.Error())
			}
		}

		tun.tunFile = file

		return nil
	}
}

func (tun *NativeTun) closeTUN() (err error) {
	tun.tunLock.Lock()
	defer tun.tunLock.Unlock()

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

func (tun *NativeTun) getTUN() (*os.File, error) {
	tun.tunLock.Lock()
	defer tun.tunLock.Unlock()

	if tun.tunFile == nil {
		// TUN device is not open (yet).
		err := tun.openTUN()
		if err != nil {
			return nil, err
		}
	}

	return tun.tunFile, nil
}

func (tun *NativeTun) Name() (string, error) {
	return tun.wt.GetInterfaceName()
}

func (tun *NativeTun) File() *os.File {
	return nil
}

func (tun *NativeTun) Events() chan TUNEvent {
	return tun.events
}

func (tun *NativeTun) Close() error {
	windows.SetEvent(tun.userClose)
	err := windows.CloseHandle(tun.userClose)

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

func (tun *NativeTun) MTU() (int, error) {
	return tun.forcedMtu, nil
}

//TODO: This is a temporary hack. We really need to be monitoring the interface in real time and adapting to MTU changes.
func (tun *NativeTun) ForceMtu(mtu int) {
	tun.forcedMtu = mtu
}

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
	}

	for {
		if tun.rdBuff.offset+packetExchangeAlignment <= tun.rdBuff.avail {
			// Get packet from the exchange buffer.
			packet := tun.rdBuff.data[tun.rdBuff.offset:]
			size := *(*uint32)(unsafe.Pointer(&packet[0]))
			pSize := packetAlign(packetExchangeAlignment + size)
			if packetSizeMax < size || tun.rdBuff.avail < tun.rdBuff.offset+pSize {
				// Invalid packet size.
				tun.rdBuff.avail = 0
				continue
			}
			packet = packet[packetExchangeAlignment : packetExchangeAlignment+size]

			// Copy data.
			copy(buff[offset:], packet)
			tun.rdBuff.offset += pSize
			return int(size), nil
		}

		// Get TUN data pipe.
		file, err := tun.getTUN()
		if err != nil {
			return 0, err
		}

		// Fill queue.
		n, err := file.Read(tun.rdBuff.data[:])
		if err != nil {
			// TUN interface stopped, failed, etc. Retry.
			tun.rdBuff.avail = 0
			tun.closeTUN()
			continue
		}
		tun.rdBuff.offset = 0
		tun.rdBuff.avail = uint32(n)
	}
}

// Note: flush() and putTunPacket() assume the caller comes only from a single thread; there's no locking.

func (tun *NativeTun) flush() error {
	// Get TUN data pipe.
	file, err := tun.getTUN()
	if err != nil {
		return err
	}

	// Flush write buffer.
	_, err = file.Write(tun.wrBuff.data[:tun.wrBuff.offset])
	tun.wrBuff.packetNum = 0
	tun.wrBuff.offset = 0
	if err != nil {
		// TUN interface stopped, failed, etc. Drop.
		tun.closeTUN()
		return err
	}

	return nil
}

func (tun *NativeTun) putTunPacket(buff []byte) error {
	size := uint32(len(buff))
	if size == 0 {
		return errors.New("Empty packet")
	}
	if size > packetSizeMax {
		return errors.New("Packet too big")
	}
	pSize := packetAlign(packetExchangeAlignment + size)

	if tun.wrBuff.packetNum >= packetExchangeMax || tun.wrBuff.offset+pSize >= packetExchangeSize {
		// Exchange buffer is full -> flush first.
		err := tun.flush()
		if err != nil {
			return err
		}
	}

	// Write packet to the exchange buffer.
	packet := tun.wrBuff.data[tun.wrBuff.offset : tun.wrBuff.offset+pSize]
	*(*uint32)(unsafe.Pointer(&packet[0])) = size
	packet = packet[packetExchangeAlignment : packetExchangeAlignment+size]
	copy(packet, buff)

	tun.wrBuff.packetNum++
	tun.wrBuff.offset += pSize

	return nil
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {
	err := tun.putTunPacket(buff[offset:])
	if err != nil {
		return 0, err
	}

	// Flush write buffer.
	return len(buff) - offset, tun.flush()
}

//
// GUID returns Windows adapter instance ID.
//
func (tun *NativeTun) GUID() windows.GUID {
	return *(*windows.GUID)(tun.wt)
}
