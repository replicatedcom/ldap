// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"gopkg.in/asn1-ber.v1"
)

const (
	EntryStatePresent = 0
	EntryStateAdd     = 1
	EntryStateModify  = 2
	EntryStateDelete  = 3
)

const (
	ControlTypePaging                 = "1.2.840.113556.1.4.319"
	ControlTypeBeheraPasswordPolicy   = "1.3.6.1.4.1.42.2.27.8.5.1"
	ControlTypeVChuPasswordMustChange = "2.16.840.1.113730.3.4.4"
	ControlTypeVChuPasswordWarning    = "2.16.840.1.113730.3.4.5"

	ControlTypeChangeNotify = "1.2.840.113556.1.4.528"

	// Content Synchronization Operation -- RFC 4533
	ControlTypeContentSync      = "1.3.6.1.4.1.4203.1.9.1.1"
	ControlTypeContentSyncState = "1.3.6.1.4.1.4203.1.9.1.2"
	ControlTypeContentSyncDone  = "1.3.6.1.4.1.4203.1.9.1.3"
	ControlTypeContentSyncInfo  = "1.3.6.1.4.1.4203.1.9.1.4"

	// Active Directory extensions
	ControlTypeDirSync   = "1.2.840.113556.1.4.841"
	ControlTypeDirSyncEx = "1.2.840.113556.1.4.529"
	ControlTypeDeleted   = "1.2.840.113556.1.4.417"
)

var ControlTypeMap = map[string]string{
	ControlTypeDeleted: "Deleted",
}

type EntryCallback func(*Entry, []byte, uint32) error
type CookieCallback func([]byte) error

type Control interface {
	GetControlType() string
	Encode() *ber.Packet
	String() string
}

func FindControl(controls []Control, controlType string) Control {
	for _, c := range controls {
		if c.GetControlType() == controlType {
			return c
		}
	}
	return nil
}

func DecodeControl(packet *ber.Packet) Control {
	controlType := packet.Children[0].Value.(string)
	criticality := false

	packet.Children[0].Description = "Control Type (" + ControlTypeMap[controlType] + ")"
	value := packet.Children[1]
	if len(packet.Children) == 3 {
		value = packet.Children[2]
		packet.Children[1].Description = "Criticality"
		criticality = packet.Children[1].Value.(bool)
	}

	value.Description = "Control Value"
	switch controlType {
	case ControlTypePaging:
		result := new(ControlPaging)
		result.decode(criticality, value)
		return result
	case ControlTypeDirSync:
		result := new(ControlDirSync)
		result.decode(criticality, value)
		return result
	case ControlTypeBeheraPasswordPolicy:
		result := NewControlBeheraPasswordPolicy()
		result.decode(criticality, value)
		return result
	case ControlTypeVChuPasswordMustChange:
		result := &ControlVChuPasswordMustChange{}
		result.decode(criticality, value)
		return result
	case ControlTypeVChuPasswordWarning:
		result := &ControlVChuPasswordWarning{Expire: -1}
		result.decode(criticality, value)
		return result
	case ControlTypeContentSyncState:
		result := &ControlContentSyncState{}
		result.decode(criticality, value)
		return result
	default:
		result := new(ControlString)
		result.ControlType = controlType
		result.decode(criticality, value)
		return result
	}
}

func encodeControls(controls []Control) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range controls {
		packet.AppendChild(control.Encode())
	}
	return packet
}
