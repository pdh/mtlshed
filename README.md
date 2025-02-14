# wtph

what the ph? Kinda like [certstrap](https://github.com/square/certstrap) but dumberer.


You supply some diceware wordlist and this script:

- Creates a CA certificate and private key
- Generates a server certificate signed by the CA
- Creates two client certificates in PFX format with password protection
- Saves all necessary files to disk

The certificates are valid for 365 days and use 2048-bit RSA keys with SHA256 for signing. You can modify the parameters in the create_cert_name function to customize the certificate details. Remember to store the passwords securely and distribute them separately from the certificates.

## usage

```
# Basic usage with defaults
python script.py

# Specify output directory and key size
python script.py --output-dir ./certs --key-size 4096

# Custom certificate details
python script.py --country GB --state London --org "My Company"

# Specify client names and passwords
python script.py --client-names client1 client2 client3 --client-passwords pass1 pass2 pass3

# Full example with multiple options
python script.py \
    --output-dir ./certs \
    --key-size 4096 \
    --valid-days 730 \
    --country US \
    --state California \
    --locality "San Francisco" \
    --org "My Company" \
    --org-unit "Engineering" \
    --email "admin@mycompany.com" \
    --server-cn "myserver.company.com" \
    --client-names webapp1 webapp2 webapp3 \
    --client-passwords secret1 secret2 secret3
```