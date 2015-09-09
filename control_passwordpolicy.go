package ldap

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

func init() {
	ControlTypeMap[ControlTypeBeheraPasswordPolicy] = "Password Policy - Behera Draft"
}

type ControlBeheraPasswordPolicy struct {
	Expire      int64
	Grace       int64
	Error       int8
	ErrorString string
}

func NewControlBeheraPasswordPolicy() *ControlBeheraPasswordPolicy {
	return &ControlBeheraPasswordPolicy{
		Expire: -1,
		Grace:  -1,
		Error:  -1,
	}
}

func (c *ControlBeheraPasswordPolicy) GetControlType() string {
	return ControlTypeBeheraPasswordPolicy
}

func (c *ControlBeheraPasswordPolicy) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeBeheraPasswordPolicy, "Control Type ("+ControlTypeMap[ControlTypeBeheraPasswordPolicy]+")"))

	return packet
}

func (c *ControlBeheraPasswordPolicy) decode(criticality bool, value *ber.Packet) {
	value.Description += "Control Value (Password Policy - Behera)"
	if value.Value != nil {
		valueChildren := ber.DecodePacket(value.Data.Bytes())
		value.Data.Truncate(0)
		value.Value = nil
		value.AppendChild(valueChildren)
	}

	sequence := value.Children[0]

	for _, child := range sequence.Children {
		if child.Tag == 0 {
			//Warning
			child := child.Children[0]
			packet := ber.DecodePacket(child.Data.Bytes())
			val, ok := packet.Value.(int64)
			if ok {
				if child.Tag == 0 {
					//timeBeforeExpiration
					c.Expire = val
					child.Value = c.Expire
				} else if child.Tag == 1 {
					//graceAuthNsRemaining
					c.Grace = val
					child.Value = c.Grace
				}
			}
		} else if child.Tag == 1 {
			// Error
			packet := ber.DecodePacket(child.Data.Bytes())
			val, ok := packet.Value.(int8)
			if !ok {
				// what to do?
				val = -1
			}
			c.Error = val
			child.Value = c.Error
			c.ErrorString = BeheraPasswordPolicyErrorMap[c.Error]
		}
	}
}

func (c *ControlBeheraPasswordPolicy) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Expire: %d  Grace: %d  Error: %d, ErrorString: %s",
		ControlTypeMap[ControlTypeBeheraPasswordPolicy],
		ControlTypeBeheraPasswordPolicy,
		false,
		c.Expire,
		c.Grace,
		c.Error,
		c.ErrorString)
}
