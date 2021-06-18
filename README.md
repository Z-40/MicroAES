# MicroAES

A pure python implementation of AES (Advanced Encryption Standard) with support for 
128, 192 and 256 bit keys and CBC, CTR, CFB and OFB modes of encryption.

#### Usage: 

    import micro_aes
    aes = micro_aes.AES(b"MyPassword", b"sAlTDaTa", 32, "sha256")
    encrypted_data = aes.encrypt(b"Send Z-40 $100", "cbc", "sha256")
    decrypted_data = aes.decrypt(encrypted_data, "cbc", "sha256")

    print(bytes.hex(encrypted_data))
    # 1bbd4a183d5c633e167d50047144ab812ebfa252da1282446a33fc681513a4d63234c18c83b82796dfafebed2714ef3c047c773b050c58048a3a1ea00bbcbd0a

    print(decrypted_data)
    # b'Send Z-40 $100'

