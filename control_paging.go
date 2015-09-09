package ldap

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

func init() {
	ControlTypeMap[ControlTypePaging] = "Paging"
}

type ControlPaging struct {
	PagingSize uint32
	Cookie     []byte
}

func NewControlPaging(pagingSize uint32) *ControlPaging {
	return &ControlPaging{PagingSize: pagingSize}
}

func (c *ControlPaging) GetControlType() string {
	return ControlTypePaging
}

func (c *ControlPaging) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypePaging, "Control Type ("+ControlTypeMap[ControlTypePaging]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Paging)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(c.PagingSize), "Paging Size"))
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

func (c *ControlPaging) decode(criticality bool, value *ber.Packet) {
	value.Description = "Control Value (Paging)"
	if value.Value != nil {
		valueChildren := ber.DecodePacket(value.Data.Bytes())
		value.Data.Truncate(0)
		value.Value = nil
		value.AppendChild(valueChildren)
	}
	value = value.Children[0]
	value.Description = "Search Control Value"
	value.Children[0].Description = "Paging Size"
	value.Children[1].Description = "Cookie"
	c.PagingSize = uint32(value.Children[0].Value.(int64))
	c.Cookie = value.Children[1].Data.Bytes()
	value.Children[1].Value = c.Cookie
}

func (c *ControlPaging) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  PagingSize: %d  Cookie: %q",
		ControlTypeMap[ControlTypePaging],
		ControlTypePaging,
		false,
		c.PagingSize,
		c.Cookie)
}

func (c *ControlPaging) SetCookie(cookie []byte) {
	c.Cookie = cookie
}
