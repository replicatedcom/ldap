package ldap

import (
	"fmt"
	"strconv"

	"gopkg.in/asn1-ber.v1"
)

func init() {
	ControlTypeMap[ControlTypeVChuPasswordMustChange] = "Password Must Change"
}

type ControlVChuPasswordMustChange struct {
	MustChange bool
}

func (c *ControlVChuPasswordMustChange) GetControlType() string {
	return ControlTypeVChuPasswordMustChange
}

func (c *ControlVChuPasswordMustChange) Encode() *ber.Packet {
	return nil
}

func (c *ControlVChuPasswordMustChange) decode(criticality bool, value *ber.Packet) {
	c.MustChange = true
}

func (c *ControlVChuPasswordMustChange) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  MustChange: %b",
		ControlTypeMap[ControlTypeVChuPasswordMustChange],
		ControlTypeVChuPasswordMustChange,
		false,
		c.MustChange)
}

type ControlVChuPasswordWarning struct {
	Expire int64
}

func (c *ControlVChuPasswordWarning) GetControlType() string {
	return ControlTypeVChuPasswordWarning
}

func (c *ControlVChuPasswordWarning) Encode() *ber.Packet {
	return nil
}

func (c *ControlVChuPasswordWarning) decode(criticality bool, value *ber.Packet) {
	expireStr := ber.DecodeString(value.Data.Bytes())

	expire, err := strconv.ParseInt(expireStr, 10, 64)
	if err != nil {
		return
	}
	c.Expire = expire
	value.Value = c.Expire
}

func (c *ControlVChuPasswordWarning) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Expire: %b",
		ControlTypeMap[ControlTypeVChuPasswordWarning],
		ControlTypeVChuPasswordWarning,
		false,
		c.Expire)
}
