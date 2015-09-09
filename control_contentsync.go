package ldap

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

func init() {
	ControlTypeMap[ControlTypeContentSync] = "Content Sync"
}

func NewControlContentSync(mode uint64, reloadHint bool, cookie []byte) *ControlContentSync {
	return &ControlContentSync{
		Criticality: true,
		Mode:        mode,
		Cookie:      cookie,
		ReloadHint:  reloadHint,
	}
}

type ControlContentSync struct {
	Criticality bool
	Mode        uint64
	Cookie      []byte
	ReloadHint  bool
}

func (c *ControlContentSync) GetControlType() string {
	return ControlTypeContentSync
}

func (c *ControlContentSync) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeContentSync, "Control Type ("+ControlTypeMap[ControlTypeContentSync]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Content Sync)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Content Sync Control Value")

	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(c.Mode), "Mode"))

	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)

	seq.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.ReloadHint, "ReloadHint"))

	p2.AppendChild(seq)

	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	packet.AppendChild(p2)
	return packet
}

func (c *ControlContentSync) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q) Criticality:%v Mode:%v ReloadHint:%v Cookie:%s",
		ControlTypeMap[ControlTypeContentSync],
		ControlTypeContentSync,
		c.Criticality,
		c.Mode,
		c.ReloadHint,
		c.Cookie)
}

func (c *ControlContentSync) SetCookie(cookie []byte) {
	c.Cookie = cookie
}
