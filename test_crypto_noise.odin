#+build ignore
package noise

import "core:crypto"
import "core:crypto/aead"
import "core:crypto/ecdh"
import "core:crypto/hash"
import "core:fmt"
import "core:math/rand"
import "core:mem"
import "core:strings"
import "core:slice"
import "core:testing"
import "core:time"

@(test)
test_noise_1000_random_protocols :: proc(t: ^testing.T) {
	// test_log := strings.builder_make()

	// any_test_failed := false
	// stopwatch : time.Stopwatch
	// time.stopwatch_start(&stopwatch)
	for i in 0..<1000 {
		protocol := random_protocol()
		protocol_name := protocol_text_from_struct(protocol)
		// protocol_name := "Noise_INpsk2_448_AESGCM_SHA256"
		// protocol, parse_error := parse_protocol_string(protocol_name)
		// fmt.println(protocol_name)
		fmt.sbprintfln(&test_log, protocol_name)
		initiator_s := GENERATE_KEYPAIR(protocol)
		responder_s := GENERATE_KEYPAIR(protocol)
		ini_rs : Maybe(ecdh.Public_Key) = nil
		res_rs : Maybe(ecdh.Public_Key) = nil
		pattern := HANDSHAKE_PATTERNS[protocol.handshake_pattern]
		fmt.sbprintfln(&test_log, "%v", pattern)
		if slice.contains(pattern.pre_messages, Pre_Token.res_s) {
			fmt.sbprintfln(&test_log, "here")
			ini_rs = responder_s.public
		}
		if slice.contains(pattern.pre_messages, Pre_Token.ini_s){
			res_rs = initiator_s.public
		}

		psk : [32]u8
		if pattern.is_psk {
			crypto.rand_bytes(psk[:])
		}

		initiator_handshakestate, ini_ini_status := handshakestate_initialize(
			true,
			nil,
			initiator_s,
			nil,
			ini_rs,
			nil,
			protocol_name = protocol_name,
			psk = psk,
		)
		responder_handshakestate, res_ini_status := handshakestate_initialize(
			false,
			nil,
			responder_s,
			nil,
			res_rs,
			nil,
			protocol_name = protocol_name,
			psk = psk,
		)
		if ini_ini_status != .Ok { any_test_failed = true}
		if res_ini_status != .Ok { any_test_failed = true}

		ini_status, res_status : NoiseStatus
		ini_cstates, res_cstates : CipherStates
		ini_message, res_message : []u8
		res_complete := false

		for {
			if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
				break
			}
			ini_cstates, res_message, ini_status = initiator_step(&initiator_handshakestate, ini_message, nil)
			if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
				break
			}
			res_cstates, ini_message, res_status = responder_step(&responder_handshakestate, res_message, nil)
		}

		if ini_cstates.c1_i_to_r != res_cstates.c1_i_to_r {any_test_failed = true}
		if ini_cstates.c2_r_to_i != res_cstates.c2_r_to_i {any_test_failed = true}

		og_test_data := make([]u8, rand.int_range(128, MAX_PACKET_SIZE-16))
		defer delete(og_test_data)
		crypto.rand_bytes(og_test_data[:])
		backup_og := slice.clone(og_test_data)
		defer delete(backup_og)

		prepared_test_data, status := prepare_message(&ini_cstates, og_test_data[:])
		decrypted_test_data, decrypt_status := open_message(&res_cstates, prepared_test_data)

		if !slice.equal(backup_og[:], decrypted_test_data) {any_test_failed = true}

		test_1000_messages(&ini_cstates, &res_cstates)

		handshakestate_destroy(&initiator_handshakestate)
		handshakestate_destroy(&responder_handshakestate)
		if i%100 == 0 {
			fmt.println(i)
		}
	}
	time.stopwatch_stop(&stopwatch)

	if any_test_failed {
		fmt.println(strings.to_string(test_log))
		fmt.println("SOME PROTOCOL FAILED!!!")
	} else {
		fmt.println("SUCCESS!!")
		fmt.println("Elapsed time: ", stopwatch._accumulation)
		fmt.println("Time per handshake and message: ", stopwatch._accumulation / 1000)
	}

	strings.builder_destroy(&test_log)

	fmt.println("SUCCESS!!")
}

test_noise_one_protocol :: proc(protocol_name: string) -> (CipherStates, CipherStates) {
	test_log := strings.builder_make()
	defer strings.builder_destroy(&test_log)
	any_test_failed := false

	sw : time.Stopwatch
	time.stopwatch_start(&sw)
	protocol, parse_error := parse_protocol_string(protocol_name)

	initiator_s := GENERATE_KEYPAIR(protocol)
	responder_s := GENERATE_KEYPAIR(protocol)
	ini_rs : Maybe(ecdh.Public_Key) = nil
	res_rs : Maybe(ecdh.Public_Key) = nil
	pattern := HANDSHAKE_PATTERNS[protocol.handshake_pattern]
	time.stopwatch_stop(&sw)
	fmt.println("time 1: ", time.stopwatch_duration(sw))

	time.stopwatch_reset(&sw)

	time.stopwatch_start(&sw)
	if slice.contains(pattern.pre_messages, Pre_Token.res_s) {
		ini_rs = responder_s.public
	}
	if slice.contains(pattern.pre_messages, Pre_Token.ini_s){
		res_rs = initiator_s.public
	}

	psk : [32]u8
	if pattern.is_psk {
		crypto.rand_bytes(psk[:])
	}

	initiator_handshakestate, ini_ini_status := handshakestate_initialize(
		true,
		nil,
		initiator_s,
		nil,
		ini_rs,
		nil,
		protocol_name = protocol_name,
		psk = psk,
	)
	responder_handshakestate, res_ini_status := handshakestate_initialize(
		false,
		nil,
		responder_s,
		nil,
		res_rs,
		nil,
		protocol_name = protocol_name,
		psk = psk,
	)

	time.stopwatch_stop(&sw)
	fmt.println("Time 2: ", time.stopwatch_duration(sw))
	if ini_ini_status != .Ok { any_test_failed = true}
	if res_ini_status != .Ok { any_test_failed = true}

	ini_status, res_status : NoiseStatus
	ini_cstates, res_cstates : CipherStates
	ini_message, res_message : []u8
	res_complete := false
	time.stopwatch_reset(&sw)
	for {
		if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
			break
		}
		ini_cstates, res_message, ini_status = initiator_step(&initiator_handshakestate, ini_message, nil)
		if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
			break
		}
		res_cstates, ini_message, res_status = responder_step(&responder_handshakestate, res_message, nil)
	}

	assert(ini_cstates.c1_i_to_r == res_cstates.c1_i_to_r)
	assert(ini_cstates.c2_r_to_i == res_cstates.c2_r_to_i)

	time.stopwatch_start(&sw)
	og_test_data := make([]u8, 65_000)
	defer delete(og_test_data)
	crypto.rand_bytes(og_test_data[:])
	backup_og := slice.clone(og_test_data)
	defer delete(backup_og)

	prepared_test_data, status := prepare_message(&ini_cstates, og_test_data[:])
	if status != .Ok {
		fmt.println(status)
		panic("   ")
	}
	decrypted_test_data, decrypt_status := open_message(&res_cstates, prepared_test_data)
	fmt.println(decrypt_status)
	time.stopwatch_stop(&sw)
	fmt.println("Time cipher: ", time.stopwatch_duration(sw))
	// fmt.println(backup_og[:])
	// fmt.println(decrypted_test_data)
	fmt.println(len(decrypted_test_data))
	fmt.println(len(backup_og))
	assert(slice.equal(backup_og[:], decrypted_test_data))

	fmt.println("SUCCESS!!")

	return ini_cstates, res_cstates
}

test_1000_messages :: proc(ini_cstates: ^CipherStates, res_cstates: ^CipherStates) {
	for i in 0..<1000 {
		ini_message : [4096]u8
		crypto.rand_bytes(ini_message[:])
		ini_message_backup: = ini_message

		prepared_ini_message, ini_prep_status := prepare_message(ini_cstates, ini_message[:])
		opened_ini_message, ini_open_status := open_message(res_cstates, prepared_ini_message)

		assert(slice.equal(ini_message_backup[:], opened_ini_message))
	}
}

@(private = "file")
random_protocol :: proc() -> Protocol {
	cipher  := random_cipher()
	dh      := random_dh()
	hash	:= random_hash()
	HandP   := Handshake_Pattern(rand.int_range(1, len(Handshake_Pattern)))
	return Protocol {
		cipher = cipher,
		dh = dh,
		hash = hash,
		handshake_pattern = HandP,
	}
}

@(private = "file")
random_cipher :: proc() -> aead.Algorithm {
	if rand.int_max(2) == 0 {
		return .AES_GCM_256
	}
	return .CHACHA20POLY1305
}

@(private = "file")
random_dh :: proc() -> ecdh.Curve {
	if rand.int_max(2) == 0 {
		return .X25519
	}
	return .X448
}

@(private = "file")
random_hash :: proc() -> hash.Algorithm {
	switch rand.int_max(4) {
	case 0: return .SHA256
	case 1: return .SHA512
	case 2: return .BLAKE2S
	case 3: return .BLAKE2B
	}
}
