package ldap

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

func init() {
	ControlTypeMap[ControlTypeContentSyncState] = "Sync State"
}

type ControlContentSyncState struct {
	State  uint32
	Uuid   []byte
	Cookie []byte
}

func (c *ControlContentSyncState) GetControlType() string {
	return ControlTypeContentSyncState
}

func (c *ControlContentSyncState) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeContentSyncState, "Control Type ("+ControlTypeMap[ControlTypeContentSyncState]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Content Sync Info)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint32(c.State), "State"))

	entryUuid := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "UUID")
	entryUuid.Value = c.Uuid
	entryUuid.Data.Write(c.Uuid)
	seq.AppendChild(entryUuid)

	if c.Cookie != nil {
		cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
		cookie.Value = c.Cookie
		cookie.Data.Write(c.Cookie)
		seq.AppendChild(cookie)
	}

	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

func (c *ControlContentSyncState) decode(criticality bool, value *ber.Packet) {
	value.Description = "Control Value (Sync State)"

	if value.Value == nil {
		return
	}

	valueChildren := ber.DecodePacket(value.Data.Bytes())
	value.Data.Truncate(0)
	value.Value = nil
	value.AppendChild(valueChildren)

	valueChildren.Children[0].Description = "Entry State"
	c.State = uint32(valueChildren.Children[0].Value.(int64))

	valueChildren.Children[1].Description = "Entry UUID"
	c.Uuid = valueChildren.Children[1].Data.Bytes()

	if len(valueChildren.Children) > 2 {
		valueChildren.Children[2].Description = "Cookie"
		c.Cookie = valueChildren.Children[2].Data.Bytes()
	}
}

func (c *ControlContentSyncState) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q) State: %d Uuid: %x  Cookie: %x",
		ControlTypeMap[ControlTypeContentSyncState],
		ControlTypeContentSyncState,
		c.State,
		c.Uuid,
		c.Cookie)
}

func (c *ControlContentSyncState) SetCookie(cookie []byte) {
	c.Cookie = cookie
}
