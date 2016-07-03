// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

// Plain returns a Mechanism that implements the PLAIN authentication mechanism
// as defined by RFC 4616. Each call to the function returns a new Mechanism
// with its own internal state. Usually identity will be left blank to act as
// username.
func Plain(identity, username, password string) Mechanism {
	return Mechanism{
		Start: func(state State) ([]byte, error) {
			if state != Initial {
				return nil, ErrInvalidState
			}
			return []byte(identity + "\x00" + username + "\x00" + password), nil
		},
		Next: func(challenge []byte) ([]byte, error) {
			return nil, ErrTooManySteps
		},
	}
}