package ldap

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

func init() {
	ControlTypeMap[ControlTypeDirSync] = "DIRSYNC"
	ControlTypeMap[ControlTypeDirSyncEx] = "DIRSYNC EX"
}

func NewControlDirSync(flags, maxAttributes uint64, cookie []byte) *ControlDirSync {
	return &ControlDirSync{
		Criticality:       true,
		Flags:             flags,
		MaxAttributeCount: maxAttributes,
		Cookie:            cookie,
	}
}

type ControlDirSync struct {
	Criticality       bool
	Flags             uint64
	MaxAttributeCount uint64
	Cookie            []byte
}

func (c *ControlDirSync) GetControlType() string {
	return ControlTypeDirSync
}

func (c *ControlDirSync) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeDirSync, "Control Type ("+ControlTypeMap[ControlTypeDirSync]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (DIRSYNC)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "DIRSYNC Control Value")

	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(c.Flags), "Flags"))
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(c.MaxAttributeCount), "MaxAttributeCount"))

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

func (c *ControlDirSync) decode(criticality bool, value *ber.Packet) {
	value.Description = "Control Value (DIRSYNC)"
	if value.Value != nil {
		valueChildren := ber.DecodePacket(value.Data.Bytes())
		value.Data.Truncate(0)
		value.Value = nil
		value.AppendChild(valueChildren)
	}
	value = value.Children[0]
	value.Description = "Search Control Value"
	value.Children[0].Description = "Flags"
	value.Children[1].Description = "MaxAttributeCount"
	value.Children[2].Description = "Cookie"
	c.Flags = uint64(value.Children[0].Value.(int64))
	c.MaxAttributeCount = uint64(value.Children[1].Value.(int64))
	c.Cookie = value.Children[2].Data.Bytes()
	value.Children[2].Value = c.Cookie
}

func (c *ControlDirSync) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q) Criticality:%v Flags:%v MaxAttributeCount:%v Cookie:%s",
		ControlTypeMap[ControlTypeDirSync],
		ControlTypeDirSync,
		c.Criticality,
		c.Flags,
		c.MaxAttributeCount,
		c.Cookie)
}

func (c *ControlDirSync) SetCookie(cookie []byte) {
	c.Cookie = cookie
}

type ControlDirSyncEx struct {
	Flag uint64
}

func NewControlDirSyncEx(flag uint64) *ControlDirSyncEx {
	return &ControlDirSyncEx{Flag: flag}
}

func (c *ControlDirSyncEx) GetControlType() string {
	return ControlTypeDirSyncEx
}

func (c *ControlDirSyncEx) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeDirSyncEx, "Control Type ("+ControlTypeMap[ControlTypeDirSyncEx]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (DIRSYNC EX)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")

	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(c.Flag), "Flag"))

	p2.AppendChild(seq)

	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	packet.AppendChild(p2)
	return packet
}

func (c *ControlDirSyncEx) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t Flag: %d",
		ControlTypeMap[ControlTypeDirSyncEx],
		ControlTypeDirSyncEx,
		true,
		c.Flag)
}
