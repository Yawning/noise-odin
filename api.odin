package noise

import "base:runtime"
import "core:crypto/ecdh"

// MAX_PACKET_SIZE is the maximum Noise message size, including TAG_SIZE
// if relevant (`seal_message`, `open_message`).
MAX_PACKET_SIZE :: 65535

// PSK_SIZE is the size of an optional handshake pre-shared symmetric key.
PSK_SIZE :: 32
// TAG_SIZE is the size of the AEAD authentication tag.
TAG_SIZE :: 16
// MAX_STEP_MSG_SIZE is the maximum per-handshake step message size,
// excluding the optional payload.
//
// `e` is DH_LEN, `s` is either DH_LEN or DH_LEN + TAG_SIZE, and there
// is a maximum of one per each message.
MAX_STEP_MSG_SIZE :: (MAX_DH_SIZE*2)+TAG_SIZE

// Status is the status of Noise protocol operation.
Status :: enum {
	Ok,

	// States
	Handshake_Pending,
	Handshake_Complete,
	Handshake_Split,
	Handshake_Failed,

	// Errors
	Invalid_Protocol_String,
	Invalid_Pre_Shared_Key,
	Invalid_DH_Key,
	No_Self_Identity,
	No_Peer_Identity,
	Unexpected_Peer_Identity,
	Unexpected_Pre_Shared_Key,

	DH_Failure,
	Invalid_Handshake_Message,

	Decryption_Failure,
	IV_Exhausted,
	Invalid_Cipher_State,
	Invalid_Destination_Buffer,
	Invalid_Payload_Message,
	Max_Packet_Size,

	Out_Of_Memory,
}

Handshake_State :: struct {
	s: ecdh.Private_Key,
	e: ecdh.Private_Key,
	rs: ecdh.Public_Key,
	re: ecdh.Public_Key,
	psk: [PSK_SIZE]byte,

	symmetric_state: Symmetric_State,
	message_pattern: ^Message_Pattern,
	current_message: int,

	status: Status,

	initiator: bool,
	pre_set_e: bool,
}

Cipher_States :: struct {
	c1_i_to_r: Cipher_State,
	c2_r_to_i: Cipher_State,

	initiator: bool,
}

@(require_results)
handshake_init :: proc(
	self: ^Handshake_State,
	initiator: bool,
	prologue: []byte,
	s: ^ecdh.Private_Key, // Our static key
	rs: ^ecdh.Public_Key, // Peer static key
	protocol_name: string,
	psk: []byte = nil,
	_e: ^ecdh.Private_Key = nil, // Our ephemeral key (for testing/RNG-less systems).
) -> Status {
	return handshakestate_Initialize(
		self,
		initiator,
		prologue,
		s,
		_e,
		rs,
		nil,
		protocol_name,
		psk,
	)
}

@(require_results)
handshake_initiator_step :: proc(
	self: ^Handshake_State,
	input_message: []byte,
	payload: []byte = nil,
	dst: []byte = nil,
	allocator := context.allocator,
) -> ([]byte, []byte, Status) {
	output_message: []byte
	payload_buffer: []byte
	status: Status

	dst := dst
	if input_message == nil {
		output_message, status = handshakestate_WriteMessage(self, payload, dst, allocator)
	} else {
		payload_buffer, status = handshakestate_ReadMessage(self, input_message, dst, allocator)
		if status == .Handshake_Pending {
			if dst != nil {
				dst = dst[len(payload_buffer):]
			}
			output_message, status = handshakestate_WriteMessage(self, payload, dst, allocator)
		}
	}

	return output_message, payload_buffer, status
}

@(require_results)
handshake_responder_step :: proc(
	self: ^Handshake_State,
	input_message: []byte,
	payload: []byte = nil,
	dst: []byte = nil,
	allocator := context.allocator,
) -> ([]byte, []byte, Status) {
	output_message: []byte

	if input_message == nil {
		return nil, nil, .Invalid_Handshake_Message
	}

	dst := dst
	payload_buffer, status := handshakestate_ReadMessage(self, input_message, dst, allocator)
	if status == .Handshake_Pending {
		if dst != nil {
			dst = dst[len(payload_buffer):]
		}
		output_message, status = handshakestate_WriteMessage(self, payload, dst, allocator)
	}

	return output_message, payload_buffer, status
}

@(require_results)
handshake_split :: proc(self: ^Handshake_State, cipher_states: ^Cipher_States) -> Status {
	if self.status != .Handshake_Complete {
		return self.status
	}

	symmetricstate_Split(&self.symmetric_state, cipher_states)
	if self.message_pattern.is_one_way {
		cipherstate_reset(&cipher_states.c2_r_to_i)
		cipher_states.c2_r_to_i.is_invalid = true
	}
	cipher_states.initiator = self.initiator
	self.status = .Handshake_Split

	return .Ok
}

@(require_results)
handshake_peer_identity :: proc(self: ^Handshake_State) -> (^ecdh.Public_Key, Status) {
	#partial switch self.status {
	case .Handshake_Complete, .Handshake_Split:
	case:
		return nil, self.status
	}

	if ecdh.curve(&self.rs) == .Invalid {
		return nil, .No_Peer_Identity
	}

	return &self.rs, .Ok
}

@(require_results)
handshake_hash :: proc(self: ^Handshake_State) -> ([]byte, Status) {
	#partial switch self.status {
	case .Handshake_Complete, .Handshake_Split:
	case:
		return nil, self.status
	}

	return symmetricstate_GetHandshakeHash(&self.symmetric_state), .Ok
}

handshake_reset :: proc(self: ^Handshake_State) {
	handshakestate_reset(self)
}

@(require_results)
seal_message :: proc(self: ^Cipher_States, ad, data: []byte, dst: []byte = nil, allocator := context.allocator) -> ([]byte, Status) {
	data_len := len(data)

	dst := dst
	did_alloc: bool
	switch {
	case dst == nil:
		err: runtime.Allocator_Error
		dst, err = make([]byte, data_len + TAG_SIZE, allocator)
		if err != nil {
			return nil, .Out_Of_Memory
		}
		did_alloc = true
	case:
		if len(dst) != data_len + TAG_SIZE {
			return nil, .Invalid_Destination_Buffer
		}
	}

	status: Status
	switch self.initiator {
	case true:
		dst, status = cipherstate_EncryptWithAd(&self.c1_i_to_r, ad, data, dst)
	case false:
		dst, status = cipherstate_EncryptWithAd(&self.c2_r_to_i, ad, data, dst)
	}
	if status != .Ok && did_alloc {
		delete(dst, allocator)
		dst = nil
	}

	return dst, status
}

@(require_results)
open_message :: proc(self: ^Cipher_States, ad, ciphertext: []byte, dst: []byte = nil, allocator := context.allocator) -> ([]byte, Status) {
	if len(ciphertext) < TAG_SIZE {
		return nil, .Invalid_Payload_Message
	}

	data_len := len(ciphertext) - TAG_SIZE

	dst := dst
	did_alloc: bool
	switch {
	case dst == nil:
		if data_len > 0 {
			err: runtime.Allocator_Error
			dst, err = make([]byte, data_len, allocator)
			if err != nil {
				return nil, .Out_Of_Memory
			}
			did_alloc = true
		}
	case:
		if len(dst) != data_len {
			return nil, .Invalid_Destination_Buffer
		}
	}

	status: Status
	switch self.initiator {
	case true:
		dst, status = cipherstate_DecryptWithAd(&self.c2_r_to_i, ad, ciphertext, dst)
	case false:
		dst, status = cipherstate_DecryptWithAd(&self.c1_i_to_r, ad, ciphertext, dst)
	}
	if status != .Ok && did_alloc {
		delete(dst, allocator)
		dst = nil
	}

	return dst, status
}

@(require_results)
rekey :: proc(self: ^Cipher_States, seal_key: bool) -> Status {
	cs: ^Cipher_State
	switch self.initiator {
	case true:
		switch seal_key {
		case true:
			cs = &self.c1_i_to_r
		case false:
			cs = &self.c2_r_to_i
		}
	case false:
		switch seal_key {
		case true:
			cs = &self.c2_r_to_i
		case false:
			cs = &self.c1_i_to_r
		}
	}

	if cs.is_invalid {
		return .Invalid_Cipher_State
	}
	if !cipherstate_HasKey(cs) {
		return .Handshake_Pending
	}

	cipherstate_Rekey(cs)

	return .Ok
}

cipherstates_reset :: proc(self: ^Cipher_States) {
	self.initiator = false
	cipherstate_reset(&self.c1_i_to_r)
	cipherstate_reset(&self.c2_r_to_i)
}
