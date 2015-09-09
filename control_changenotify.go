package ldap

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

func init() {
	ControlTypeMap[ControlTypeChangeNotify] = "Change Notification"
}

func NewControlChangeNotify() *ControlChangeNotify {
	return &ControlChangeNotify{Criticality: true}
}

type ControlChangeNotify struct {
	Criticality bool
	Cookie      []byte
}

func (c *ControlChangeNotify) GetControlType() string {
	return ControlTypeChangeNotify
}

func (c *ControlChangeNotify) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeChangeNotify, "Control Type ("+ControlTypeMap[ControlTypeChangeNotify]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Change Notification)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)

	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	packet.AppendChild(p2)
	return packet
}

func (c *ControlChangeNotify) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Cookie: %q",
		ControlTypeMap[ControlTypeChangeNotify],
		ControlTypeChangeNotify,
		c.Criticality,
		c.Cookie)
}

func (c *ControlChangeNotify) SetCookie(cookie []byte) {
	c.Cookie = cookie
}
