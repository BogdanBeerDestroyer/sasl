// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

// A Client represents a stateful SASL client that can attempt to negotiate auth
// using its underlying Mechanism. Client's should not be used from multiple
// goroutines, and must be reset between negotiation attempts.
type Client struct {
	Mechanism Mechanism

	state State
	err   error
}

// Step attempts to transition the SASL mechanism to its next state. If Step is
// called after a previous invocation generates an error (and the Client has not
// been reset to its initial state), Step panics.
func (c *Client) Step(challenge []byte) (more bool, resp []byte, err error) {
	if c.Err() != nil {
		panic(c.Err())
	}

	switch c.state & stateMask {
	case Initial:
		more, resp, c.err = c.Mechanism.Start()
		c.state = AuthTextSent
		return more, resp, c.err
	case AuthTextSent:
		more, resp, c.err = c.Mechanism.Next(c.state, challenge)
		c.state = ResponseSent
		return more, resp, c.err
	case ResponseSent:
		more, resp, c.err = c.Mechanism.Next(c.state, challenge)
		c.state = ValidServerResponse
		return more, resp, c.err
	case ValidServerResponse:
		more, resp, c.err = c.Mechanism.Next(c.state, challenge)
		return more, resp, c.err
	}

	return false, nil, ErrInvalidState
}

// Err returns any errors generated by the SASL Client.
func (c *Client) Err() error {
	return c.err
}

// State returns the internal state of the SASL Client.
func (c *Client) State() State {
	return c.state
}

// Reset resets the Client to its initial state so that it can be reused in
// another SASL exchange.
func (c *Client) Reset() {
	c.state = State(0)
	c.err = nil
}
