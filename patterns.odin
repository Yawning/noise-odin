package noise

// Supported handshake patterns will be listed here.
Handshake_Pattern :: enum {
	Invalid,
	// One way patterns
	N,
	K,
	X,
	// Fundamental patterns
	XX,
	NK,
	NN,
	KN,
	KK,
	NX,
	KX,
	XN,
	IN,
	XK,
	IK,
	IX,
	// psk patterns
	NNpsk0,
	NNpsk2,
	NKpsk0,
	NKpsk2,
	NXpsk2,
	XNpsk3,
	XKpsk3,
	XXpsk3,
	KNpsk0,
	KNpsk2,
	KKpsk0,
	KKpsk2,
	KXpsk2,
	INpsk1,
	INpsk2,
	IKpsk1,
	IKpsk2,
	IXpsk2,
}

HANDSHAKE_PATTERNS := [Handshake_Pattern]^MessagePattern {
	.Invalid = nil,
	.N = &PATTERN_N,
	.K = &PATTERN_K,
	.X = &PATTERN_X,
	.XX = &PATTERN_XX,
	.NK = &PATTERN_NK,
	.NN = &PATTERN_NN,
	.KN = &PATTERN_KN,
	.KK = &PATTERN_KK,
	.NX = &PATTERN_NX,
	.KX = &PATTERN_KX,
	.XN = &PATTERN_XN,
	.IN = &PATTERN_IN,
	.XK = &PATTERN_XK,
	.IK = &PATTERN_IK,
	.IX = &PATTERN_IX,
	.NNpsk0 = &PATTERN_NNpsk0,
	.NNpsk2 = &PATTERN_NNpsk2,
	.NKpsk0 = &PATTERN_NKpsk0,
	.NKpsk2 = &PATTERN_NKpsk2,
	.NXpsk2 = &PATTERN_NXpsk2,
	.XNpsk3 = &PATTERN_XNpsk3,
	.XKpsk3 = &PATTERN_XKpsk3,
	.XXpsk3 = &PATTERN_XXpsk3,
	.KNpsk0 = &PATTERN_KNpsk0,
	.KNpsk2 = &PATTERN_KNpsk2,
	.KKpsk0 = &PATTERN_KKpsk0,
	.KKpsk2 = &PATTERN_KKpsk2,
	.KXpsk2 = &PATTERN_KXpsk2,
	.INpsk1 = &PATTERN_INpsk1,
	.INpsk2 = &PATTERN_INpsk2,
	.IKpsk1 = &PATTERN_IKpsk1,
	.IKpsk2 = &PATTERN_IKpsk2,
	.IXpsk2 = &PATTERN_IXpsk2,
}

// ------------- ONE WAY PATTERNS ---------------------------------------------------------

// N:
//   <- s
//   ...
//   -> e, es
@(rodata)
PATTERN_N : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.e, .es},
	},
}

// K:
//   -> s
//   <- s
//   ...
//   -> e, es, ss
@(rodata)
PATTERN_K : MessagePattern = {
	pre_messages = {.ini_s, .res_s},
	messages = {
		{.e, .es, .ss},
	},
}

// X:
//   <- s
//   ...
//   -> e, es, s, ss
@(rodata)
PATTERN_X : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.e, .es, .s, .ss},
	},
}

// ----------------------------------------------------------------------------------------

// ------------- FUNDAMENTAL PATTERNS -----------------------------------------------------

// XX:
//   -> e
//   <- e, ee, s, es
//   -> s, se
@(rodata)
PATTERN_XX : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e},
		{.e, .ee, .s, .es},
		{.s, .se},
	},
}

// NK:
//   <- s
//   ...
//   -> e, es
//   <- e, ee
@(rodata)
PATTERN_NK : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.e, .es},
		{.e, .ee},
	},
}

// NN:
//   -> e
//   <- e, ee
@(rodata)
PATTERN_NN : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e},
		{.e, .ee},
	},
}

// KN:
//   -> s
//   ...
//   -> e
//   <- e, ee, se
@(rodata)
PATTERN_KN : MessagePattern = {
	pre_messages = {.ini_s},
	messages = {
		{.e,},
		{.e, .ee, .se},
	},
}

// KK:
//   -> s
//   <- s
//   ...
//   -> e, es, ss
//   <- e, ee, se
@(rodata)
PATTERN_KK : MessagePattern = {
	pre_messages = {.ini_s, .res_s},
	messages = {
		{.e, .es, .ss},
		{.e, .ee, .se},
	},
}

// NX:
//   -> e
//   <- e, ee, s, es
@(rodata)
PATTERN_NX : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e},
		{.e, .ee, .s, .es},
	},
}

// KX:
//   -> s
//   ...
//   -> e
//   <- e, ee, se, s, es
@(rodata)
PATTERN_KX : MessagePattern = {
	pre_messages = {.ini_s},
	messages = {
		{.e},
		{.e, .ee, .se, .s, .es},
	},
}

// XN:
//   -> e
//   <- e, ee
//   -> s, se
@(rodata)
PATTERN_XN : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e},
		{.e, .ee},
		{.s, .se},
	},
}

// IN:
//   -> e, s
//   <- e, ee, se
@(rodata)
PATTERN_IN : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e, .s},
		{.e, .ee, .se},
	},
}

// XK:
//   <- s
//   ...
//   -> e, es
//   <- e, ee
//   -> s, se
@(rodata)
PATTERN_XK : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.e, .es},
		{.e, .ee},
		{.s, .se},
	},
}

// IK:
//   <- s
//   ...
//   -> e, es, s, ss
//   <- e, ee, se
@(rodata)
PATTERN_IK : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.e, .es, .s, .ss},
		{.e, .ee, .se},
	},
}

// IX:
//   -> e, s
//   <- e, ee, se, s, es
@(rodata)
PATTERN_IX :  MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e, .s},
		{.e, .ee, .se, .s, .es},
	},
}

// ----------------------------------------------------------------------------------------

// ------------- PSK PATTERNS -------------------------------------------------------------

// NNpsk0:
//   -> psk, e
//   <- e, ee
@(rodata)
PATTERN_NNpsk0 : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.psk, .e},
		{.e, .ee},
	},
}

// NNpsk2:
//   -> e
//   <- e, ee, psk
@(rodata)
PATTERN_NNpsk2 : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e},
		{.e, .ee, .psk},
	},
}

// NKpsk0:
//   <- s
//   ...
//   -> psk, e, es
//   <- e, ee
@(rodata)
PATTERN_NKpsk0 : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.psk, .e, .es},
		{.e, .ee},
	},
}

// NKpsk2:
//   <- s
//   ...
//   -> e, es
//   <- e, ee, psk
@(rodata)
PATTERN_NKpsk2 : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.e, .es},
		{.e, .ee, .psk},
	},
}

//  NXpsk2:
//	-> e
//	<- e, ee, s, es, psk
@(rodata)
PATTERN_NXpsk2 : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e},
		{.e, .ee, .s, .es, .psk},
	},
}

//  XNpsk3:
//	-> e
//	<- e, ee
//	-> s, se, psk
@(rodata)
PATTERN_XNpsk3 : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e},
		{.e, .ee},
		{.s, .se, .psk},
	},
}

//  XKpsk3:
//	<- s
//	...
//	-> e, es
//	<- e, ee
//	-> s, se, psk
@(rodata)
PATTERN_XKpsk3 : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.e, .es},
		{.e, .ee},
		{.s, .se, .psk},
	},
}

//  XXpsk3:
//	-> e
//	<- e, ee, s, es
//	-> s, se, psk
@(rodata)
PATTERN_XXpsk3 : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e},
		{.e, .ee, .s, .es},
		{.s, .se, .psk},
	},
}

//   KNpsk0:
//	 -> s
//	 ...
//	 -> psk, e
//	 <- e, ee, se
@(rodata)
PATTERN_KNpsk0 : MessagePattern = {
	pre_messages = {.ini_s},
	messages = {
		{.psk, .e},
		{.e, .ee, .se},
	},
}

//   KNpsk2:
//	 -> s
//	 ...
//	 -> e
//	 <- e, ee, se, psk
@(rodata)
PATTERN_KNpsk2 : MessagePattern = {
	pre_messages = {.ini_s},
	messages = {
		{.e},
		{.e, .ee, .se, .psk},
	},
}

//   KKpsk0:
//	 -> s
//	 <- s
//	 ...
//	 -> psk, e, es, ss
//	 <- e, ee, se
@(rodata)
PATTERN_KKpsk0 : MessagePattern = {
	pre_messages = {.ini_s, .res_s},
	messages = {
		{.psk, .e, .es, .ss},
		{.e, .ee, .se},
	},
}

//   KKpsk2:
//	 -> s
//	 <- s
//	 ...
//	 -> e, es, ss
//	 <- e, ee, se, psk
@(rodata)
PATTERN_KKpsk2 : MessagePattern = {
	pre_messages = {.ini_s, .res_s},
	messages = {
		{.e, .es, .ss},
		{.e, .ee, .se, .psk},
	},
}

//	KXpsk2:
//	  -> s
//	  ...
//	  -> e
//	  <- e, ee, se, s, es, psk
@(rodata)
PATTERN_KXpsk2 : MessagePattern = {
	pre_messages = {.ini_s},
	messages = {
		{.e},
		{.e, .ee, .se, .s, .es, .psk},
	},
}

//	INpsk1:
//	  -> e, s, psk
//	  <- e, ee, se
@(rodata)
PATTERN_INpsk1 : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e, .s, .psk},
		{.e, .ee, .se},
	},
}

//	INpsk2:
//	  -> e, s
//	  <- e, ee, se, psk
@(rodata)
PATTERN_INpsk2 : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e, .s},
		{.e, .ee, .se, .psk},
	},
}

//	IKpsk1:
//	  <- s
//	  ...
//	  -> e, es, s, ss, psk
//	  <- e, ee, se
@(rodata)
PATTERN_IKpsk1 : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.e, .es, .s, .ss, .psk},
		{.e, .ee, .se},
	},
}

//	IKpsk2:
//	  <- s
//	  ...
//	  -> e, es, s, ss
//	  <- e, ee, se, psk
@(rodata)
PATTERN_IKpsk2 : MessagePattern = {
	pre_messages = {.res_s},
	messages = {
		{.e, .es, .s, .ss},
		{.e, .ee, .se, .psk},
	},
}

//	IXpsk2:
//	  -> e, s
//	  <- e, ee, se, s, es, psk
@(rodata)
PATTERN_IXpsk2 : MessagePattern = {
	pre_messages = nil,
	messages = {
		{.e, .s},
		{.e, .ee, .se, .s, .es, .psk},
	},
}
