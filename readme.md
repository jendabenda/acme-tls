# acme-tls

This tools can be used to obtain domain certificates using ACME `tls-alpn-01` challenge.
It checks domain certificates once a day and renews them if necessary.
Use reverse proxy (nginx, apache, ...) for routing https traffic to `acme-tls`
validation server. Supported cryptographic primitive is elliptic curve secp384r1.

## Features
 * domain certificates using ACME protocol, `tls-alpn-01` challenge
 * ACME account management
 * domain certificates revocation
 * elliptic curve cryptography
 * no dependencies apart from `python` and `openssl`
 * robust, covered by tests

## Quick start
```bash
mkdir account_path
cat > account_path/config         # paste configuration
cat > account_path/domains.list   # paste domains
acme-tls new-account account_path # create new account
# configure reverse proxy to forward traffic to acme-tls validations server
acme-tls run account_path         # obtain certificates, monitor and renew if necessary
# domain certificates are stored in acount_path/certificates
```

**account_path/config**
```bash
acme = letsencrypt  # acme certificate authority, i.e. letsencrypt,
                    # letsencrypt_test or acme directory url
contact =     # contact information for certificate authority, i.e. user@example.org, optional
host = ::1    # validation server hostname
port = 7443   # validation server port
group =       # user group for generated certificates, i.e. www-data, optional
schedule = 4  # hour which acme-tls tries to check and renew domain certificates, optional
done_cmd =    # command to be run after successful batch with new domain certificates, optional
```

**account_path/domains.list**
```bash
example.org
example.net
example.com, subdomain.example.com  # create multidomain certificate
```

**nginx configuration**
```nginx
# load stream module
load_module /usr/lib/nginx/modules/ngx_stream_module.so;

# you original nginx configuration
...

stream {
    map $ssl_preread_alpn_protocols $tls_port {
        ~\bacme-tls/1\b 7443;
        default 443;
    }

    server {
        listen [::]:443;
        proxy_pass [::1]:$tls_port;
        ssl_preread on;
    }
}
```

## License

Author: Jan Procházka \
License: none, public domain
