# acme-tls

`acme-tls` creates and validates domain certificates using ACME `tls-alpn-01` challenge.
`acme-tls` checks domain certificates once a day at 4am, accepting validation challenges
on ::1 port 7443, by default. It reloads configuration with certificates recheck
on HUP signal. Use reverse proxy (nginx, apache, ...) for routing https traffic
to either your https server or `acme-tls`. Supported crypto is elliptic curve `secp384r1`.

## Quick start
 1. create `account` directory to store account key and certificates
 2. create `account/domains.list` with domains and their subdomains on each line
 3. setup reverse proxy to redirect `tls-alpn-01` challenges to `acme-tls` validation server
 4. create account key and run validation server with (assuming [let's encrypt](https://letsencrypt.org/) as CA)
    `acme-tls.py --path account --acme letsencrypt --new-account-key --schedule once`
 5. check if certificates were generated correctly, run validation server (assuming nginx proxy)
    `acme-tls.py --path account --acme letsencrypt --done-cmd 'systemctl reload nginx'`

## Example configuration:

Configuration is saved in `account/domains.list`
```bash
example.org
example.net
example.com, subdomain.example.com  # create multidomain certificate
```

## Features
 * domain certificates using ACME protocol, `tls-alpn-01` challenge
 * elliptic curve cryptography certificates
 * no dependencies apart from `python` and `openssl`
 * small, test covered, auditable

## License

Author: Jan Procházka
License: none, public domain

## Extra

### Sample nginx configuration
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

