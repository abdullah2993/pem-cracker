# pem-cracker
Crack encrypted PEM with bruteforce

## Usage
```
Usage: pem-cracker private_key public_key
  -charset string
        Character set to use for bruteforce (default "abcdefghijklmnopqrstuvwxyz0123456789")
  -max int
        Maxmimum length of password phrase (default 8)
  -min int
        Minimum length of password phrase (default 1)
  -parallel int
        Numbers of threads to use (default 8)
  ```