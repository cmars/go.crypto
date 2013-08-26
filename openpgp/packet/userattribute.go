// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"image"
	"image/jpeg"
	"io"
	"io/ioutil"
)

const UserAttrImageSubpacket = 1

// UserAttribute is capable of storing other types of data about a user
// beyond name, email and a text comment. In practice, user attributes are typically used
// to store a signed thumbnail photo JPEG image of the user.
// See RFC 4880, section 5.12.
type UserAttribute struct {
	Contents []*OpaqueSubpacket
}

// NewUserAttributePhoto creates a user attribute packet
// containing the given images.
func NewUserAttributePhoto(photos ...image.Image) (uat *UserAttribute, err error) {
	uat = new(UserAttribute)
	for _, photo := range photos {
		buf := bytes.NewBuffer(nil)
		// RFC 4880, Section 5.12.1.
		data := []byte{
			0x10, 0x0, 0x01, 0x01,
			0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0}
		_, err = buf.Write(data)
		if err != nil {
			return
		}
		err = jpeg.Encode(buf, photo, nil)
		if err != nil {
			return
		}
		uat.Contents = append(uat.Contents, &OpaqueSubpacket{
			Length: uint32(buf.Len()), SubType: UserAttrImageSubpacket,
			Contents: buf.Bytes()})
	}
	return
}

// NewUserAttribute creates a new user attribute packet containing the given subpackets.
func NewUserAttribute(contents ...*OpaqueSubpacket) *UserAttribute {
	return &UserAttribute{Contents: contents}
}

func (uat *UserAttribute) parse(r io.Reader) (err error) {
	// RFC 4880, section 5.13
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return
	}
	uat.Contents, err = OpaqueSubpackets(b)
	return
}

// Serialize marshals the user attribute to w in the form of an OpenPGP packet, including
// header.
func (uat *UserAttribute) Serialize(w io.Writer) (err error) {
	buf := bytes.NewBuffer(nil)
	for _, sp := range uat.Contents {
		sp.Serialize(buf)
	}
	err = serializeHeader(w, packetTypeUserAttribute, buf.Len())
	if err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return
}

// ImageData returns zero or more byte slices, each containing
// JPEG File Interchange Format (JFIF), for each photo in the
// the user attribute packet.
func (uat *UserAttribute) ImageData() (imageData [][]byte) {
	for _, sp := range uat.Contents {
		if sp.SubType == UserAttrImageSubpacket {
			imageData = append(imageData, sp.Contents[16:])
		}
	}
	return
}
