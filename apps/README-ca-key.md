# CA Private Key Generation

This directory requires a private key file `ca-key.pem` for certificate authority operations during testing and development.

## Generate the private key:

```bash
openssl genrsa -out apps/ca-key.pem 2048
```

## Security Note:
- Never commit private key files to version control
- The `ca-key.pem` file is ignored by git for security reasons
- Generate a new key for each development environment
- Keep private keys secure and do not share them
