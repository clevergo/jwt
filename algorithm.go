// Copyright 2016 HeadwindFly. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jwt

type Algorithm interface {
	Encrypt(data string) (string, error)
	Verify(data, signature string) error
}
