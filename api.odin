package noise

import "core:crypto/ecdh"
import "core:mem"

// This file defines the API for the noise protocol package.
// You should never need to call an internals procedure
// or use an internals type.

// In general, to complete a noise handshake you must:
//
// - If you are initiating the connection, call initiator_step
//   passing nil to the input_message parameter.
//
// - Send the resulting []u8 to the responder (genrally a server) with
//   the stream method of your choice (see examples)
//
// - If the status code of the initiator_step call was
//   `.Handshake_Complete`, you will have received a valid
//   `CipherStates` struct. Otherwise, read the response from the
//   responder and feed the response data as the input_message to
//   the next call to initiator_step until it returns
//   `.Handshake_Complete`. You will then have a `CipherStates` struct
//   That you can pass to the prepare_message and open_message procedures
//   to prepare messages for sending to the responder and for opening
//   messages sent by the responder.
//
// - If you are the responder, the method is much the same, except you
//   must pass a valid input_message received from an initiator to the
//   first call to responder_step. Repeat until the returned status is
//   `.Handshake_Complete`.

// A noise_networking package is available to provide a simple abstraction layer for using noise over TCP. The design
// intent of the noise_networking package is to work well with odins nbio.

MAX_PACKET_SIZE :: 65535

// XXX: -> Status
NoiseStatus :: enum {
	Ok,
	Decryption_failed_to_authenticate,
	Protocol_could_not_be_parsed,
	Pending_Handshake,
	Handshake_Complete,
	rs_not_set_for_s_pre_message,
	out_of_memory,
	invalid_message_passed_to_read_message,
	tried_to_encrypt_message_bigger_than_MAX_PACKET_SIZE,
}

HandshakeState :: struct {
	symmetricstate: SymmetricState,
	s: Maybe(KeyPair),
	e: Maybe(KeyPair),
	rs: Maybe(ecdh.Public_Key),
	re: Maybe(ecdh.Public_Key),
	initiator: bool,
	message_pattern: ^Message_Pattern,
	current_token: int,
	psk: [32]u8,
}

SymmetricState :: struct {
	cipherstate: CipherState,
	ck: []u8,
	h: []u8,
	allocator: mem.Allocator,
	backing: ^mem.Dynamic_Arena,
}

CipherState :: struct {
	protocol: Protocol,
	k: [32]u8,
	n: u64,
}

CipherStates :: struct {
	c1_i_to_r: CipherState,
	c2_r_to_i: CipherState,
	initiator: bool,
}

// XXX/yeet: private key contains public key.
KeyPair :: struct {
	public: ecdh.Public_Key,
	private: ecdh.Private_Key,
}

// XXX: We are not *THAT* opinionated, yeet.
// DEFAULT_PROTOCOL_NAME :: internals.DEFAULT_PROTOCOL_NAME
// DEFAULT_PROTOCOL :: internals.DEFAULT_PROTOCOL

// parse_protocol_string :: internals.parse_protocol_string

// Keeps track of the 16 byte tag without relying on the input plaintext
// having a spare 16 byte capacity
CryptoBuffer :: struct {
	main_body: []u8,
	tag: [16]u8,
}

// cryptobuffer_from_slice :: internals.cryptobuffer_from_slice

initiator_step :: proc(handshakestate: ^HandshakeState, input_message: []u8, payload : []u8 = nil, allocator := context.allocator) -> (CipherStates, []u8, NoiseStatus) {
	output_message : []u8
	c1, c2 : CipherState
	status : NoiseStatus
	payload_buffer : []u8

	if input_message == nil {
		output_message, c1, c2, status = handshakestate_write_message(handshakestate, payload, allocator)
	} else {
		payload_buffer, c1, c2, status = handshakestate_read_message(handshakestate, input_message)
		if status != .Handshake_Complete {
			output_message, c1, c2, status = handshakestate_write_message(handshakestate, payload, allocator)
		}
	}

	return CipherStates{c1_i_to_r = c1, c2_r_to_i = c2, initiator = true}, output_message, status
}

responder_step :: proc(handshakestate: ^HandshakeState, input_message: []u8, payload : []u8 = nil, allocator := context.allocator) -> (CipherStates, []u8, NoiseStatus) {
	output_message : []u8
	if input_message == nil {
		return {}, {}, .invalid_message_passed_to_read_message,
	}

	payload_buffer, c1, c2, status := handshakestate_read_message(handshakestate, input_message)
	if status != .Handshake_Complete {
		output_message, c1, c2, status = handshakestate_write_message(handshakestate, payload, allocator)
	}

	return CipherStates{c1_i_to_r = c1, c2_r_to_i = c2, initiator = false}, output_message, status
}

// This function will overwrite "data" with the encrypted data
prepare_message :: proc(cstates: ^CipherStates, data: []u8) -> (CryptoBuffer, NoiseStatus) {
	result : CryptoBuffer
	status : NoiseStatus
	switch cstates.initiator {
	case true:
		result, status = cipherstate_EncryptWithAd(&cstates.c1_i_to_r, nil, data)
	case false:
		result, status = cipherstate_EncryptWithAd(&cstates.c2_r_to_i, nil, data)
	}
	return result, status
}

// This function will overwrite the "encrypted_message" with the decrypted data
open_message :: proc(cstates: ^CipherStates, encrypted_message: CryptoBuffer) -> ([]u8, NoiseStatus) {
	result : []u8
	status : NoiseStatus
	switch cstates.initiator {
	case true:
		result, status = cipherstate_DecryptWithAd(&cstates.c2_r_to_i, nil, encrypted_message)
	case false:
		result, status = cipherstate_DecryptWithAd(&cstates.c1_i_to_r, nil, encrypted_message)
	}
	return result, status
}
