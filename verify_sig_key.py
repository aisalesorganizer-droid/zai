
import hmac, hashlib, json

KNOWN_SAMPLES = [
    # (prompt, timestamp_ms, expected_sig)  — acc1, acc2, acc3 cross-verified
    ("test_alpha_001", 1773750230717, "12d548f2fb22be5328dd00f8b630a67195cfc73c4118131a11af928a0a559cf5"),
    ("test_beta_002",  1773750256199, "083cd9c51bc9733c58e105244fdecdcf8eecad592be6b3578fbf27891980e930"),
    ("test_gamma_003", 1773750272484, "3f565d86118e509152875b3404fca69e772f48185f665968ca7375caa9507458"),
    ("test_alpha_001", 1773750505430, "355875f4d2d89cd6b1b03770549b3ca5d282ab1bc7afb1ec0ee4f19b55f84425"),
    ("test_beta_002",  1773750519233, "0d90022c41ad144f01f9945995da8e33cd3f2510c25528736ef7561661deb388"),
    ("test_gamma_003", 1773750569230, "208562c1283d58a07e5377857c3b1c9a174b5ff8b94f8c1a9529710c462153ff"),
    ("test_alpha_001", 1773750737541, "d06d1710c2f3f0e812f56af25f1e3a5031625517de10ce8e23e7322ac911e04e"),
    ("test_beta_002",  1773750768437, "8720afacb53cb27885d2fd2c5dc58d22f3ba1c09ffad2b3d30982468a71de8b7"),
    ("test_gamma_003", 1773750811244, "e32583bd117627f4215f94dbdbce5c38105416c2a5ee080e44452b06933ff053"),
    # + 9 more agent-based (available in script)
]

def verify_key(key_hex: str, verbose=True) -> bool:
    try:
        key_bytes = bytes.fromhex(key_hex)
    except Exception:
        key_bytes = key_hex.encode()

    hits = 0
    for prompt, ts, expected in KNOWN_SAMPLES:
        msg = (str(ts) + prompt).encode()
        computed = hmac.new(key_bytes, msg, hashlib.sha256).hexdigest()
        match = computed == expected
        if match:
            hits += 1
        if verbose:
            status = "✅" if match else "❌"
            print(f"  {status} ts={ts} prompt={prompt[:16]} -> {computed[:16]}...")
    
    print(f"\nResult: {hits}/{len(KNOWN_SAMPLES)} verified")
    return hits == len(KNOWN_SAMPLES)

def compute_signature(key_hex: str, prompt: str, timestamp: int) -> str:
    key_bytes = bytes.fromhex(key_hex)
    msg = (str(timestamp) + prompt).encode()
    return hmac.new(key_bytes, msg, hashlib.sha256).hexdigest()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        # Try to load from sig_key_result.json
        try:
            with open("sig_key_result.json") as f:
                result = json.load(f)
            key = result["hmac_key_hex"]
            print(f"Testing key from sig_key_result.json: {key[:16]}...")
        except FileNotFoundError:
            print("Usage: python verify_sig_key.py <key_hex>")
            print("   Or: run extract_hmac_key.py first to populate sig_key_result.json")
            sys.exit(1)
    else:
        key = sys.argv[1]
    
    verify_key(key)
