# Cryptography Task Solution


## Step-by-Step Explanation

### Step 1: Finding Correct Key
- Calculated SHA-256 hash for each of the 3 provided keys
- Compared each hash with the given hash value
- Key #2 matched → `54684020247570407220244063724074`

### Step 2: Decrypting Message
- Used the correct key from Step 1
- Applied AES-128-CBC decryption with provided IV
- Converted decrypted bytes to UTF-8 string
- Result → `Hello Blockchain!`

### Step 3: Generating EC Key Pair
- Created ECDSA instance with NIST P-256 curve
- Exported public key in PEM format (SubjectPublicKeyInfo)
- Exported private key in PEM format (PKCS#8)

### Step 4: Creating Digital Signature
- Signed the decrypted message bytes using ECDSA
- Used SHA-256 as hashing algorithm
- Exported signature in Base64 format
- Verified signature → `True`

---

## Output
![img.png](img.png)