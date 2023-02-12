# No Files Left To Cry

atk refers to attacker
trg refers to target

- [ ] generate a rsa key pair
- [ ] encrypt the target's private key with our public key and store it on the target's device
- [ ] traverse through the files
  - [ ] generate an aes key
  - [ ] encrypt aes key with target's public key and store it
  - [ ] encrypt the file with aes
  - [ ] remove the original file