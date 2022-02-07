#!/usr/bin/env python3
"""
acme-tls creates and validates domain certificates using ACME tls-alpn-01 challenge.
acme-tls checks domain certificates once a day at 4am, accepting validation challenges
on ::1 port 7443, by default. It reloads configuration with certificates recheck
on HUP signal. Use reverse proxy (nginx, apache, ...) for routing https traffic
to either your https server or acme-tls. Supported crypto is elliptic curve secp384r1.

Quick start:
 1. create account directory to store account key and certificates
 2. create account/domains.list with domains and their subdomains on each line
 3. setup reverse proxy to redirect tls-alpn-01 challenges to acme-tls validation server
 4. create account key and run validation server with (assuming letsencrypt as CA)
    acme-tls.py --path account --acme letsencrypt --new-account-key --schedule once
 5. check if certificates were generated correctly, run validation server (assuming nginx proxy)
    acme-tls.py --path account --acme letsencrypt --done-cmd 'systemctl reload nginx'

Example domains.list configuration:

example.org
example.net
example.com, subdomain.example.com  # create multidomain certificate

Author: Jan Prochazka
License: none, public domain
"""
"""
acme-tls return values
 0 ok
 1 runtime error
 2 program argument error
 3 unhandled error
"""

import argparse
import subprocess
import json
import os
import sys
import base64
import binascii
import time
import hashlib
import re
import ssl
import tempfile
import socketserver
import threading
import socket
import signal
import traceback
import random
import grp
import textwrap
from datetime import datetime, timedelta
from threading import Event
from multiprocessing import Process, Queue
from urllib.request import urlopen, Request
from urllib.parse import urlparse

# TODO server tests


class cfg:
    """
    Server configuration
    """
    # server ciphers
    server_ciphers = ('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256')

    # prepared acme directory urls
    acme_directories = {
        'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
        'letsencrypt_staging': 'https://acme-staging-v02.api.letsencrypt.org/directory',
    }

    # certificate expiration times in days
    validity_reserve = 30
    temporary_certs_expiration = 365

    # number of seconds to poll
    acme_polling_timeout = 10 * 60
    server_polling_timeout = 60

    # elliptic curve name
    ec_curve = 'secp384r1'

    # file names
    fallback_key = 'fallback.key'
    fallback_cert = 'fallback.crt'
    domain_key = 'domain.key'
    domain_cert = 'domain.crt'
    account_key_name = 'account.key'
    domains_list_name = 'domains.list'
    certificates_path = 'certificates'
    challenges_path = 'challenges'
    check_file = '.check'

    # domain separators
    domain_separator = re.compile(r'[ ,\t]')

    # invalid SNI, used for watchdog check
    invalid_sni = '_'


# ================
# common funcitons
# ================


class CheckError(RuntimeError):
    """
    Error thrown by various checks
    """
    pass


def check_server(host, port):
    """
    Check validation server
    """
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['acme-tls/1'])
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        server_check_timeout= 5
        with socket.create_connection((host, port), timeout=server_check_timeout) as sock:
            sock = ctx.wrap_socket(sock, server_hostname=cfg.invalid_sni)
            sock.close()
    except Exception as exc:
        raise CheckError(exc)


def run_cmd(cmd_list, cmd_input=None, err_msg='cannot run command'):
    """
    Run external commands
    """
    sys.stdout.flush()
    proc = subprocess.run(cmd_list, input=cmd_input, capture_output=True)
    if proc.returncode != 0:
        proc_err = textwrap.indent(proc.stderr.decode('utf8'), '> ')
        raise RuntimeError(f'{err_msg}\n{proc_err}')

    return proc.stdout


def b64(b):
    """
    base64 encode for jose spec
    """
    return base64.urlsafe_b64encode(b).decode('utf8').replace('=', '')


def safe_remove(path):
    """
    Safely remove a file
    """
    try:
        os.unlink(path)
    except Exception:
        pass


def check_pid(pid):
    """
    Check if pid exists
    """
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def safe_kill(pid):
    """
    Kill process with SIGKILL
    """
    if pid is None:
        return

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def get_certificate_expiration(path):
    """
    Get certificate expiration time
    """
    if not os.path.isfile(path):
        raise FileNotFoundError()

    end_date = run_cmd([
        'openssl', 'x509',
        '-in', path,
        '-noout',
        '-enddate',
    ], err_msg='cannot get certificate information')
    end_date = end_date.split(b'=')[1].decode('utf8').strip()

    return datetime.strptime(end_date, '%b %d %H:%M:%S %Y %Z')


# =================
# validation server
# =================


def generate_fallback_certificates(fallback_key, fallback_cert):
    """
    Generate fallback certificates
    """
    # check expiration time
    try:
        expiration = get_certificate_expiration(fallback_cert)
        if expiration > datetime.now() + timedelta(days=cfg.validity_reserve) and os.path.isfile(fallback_key):
            return
    except FileNotFoundError:
        pass  # expected, certs were not generated yet
    except Exception as exc:
        print(f'server: cannot get fallback certificate expiration time, renewing: {exc}')

    # remove old fallbacks
    safe_remove(fallback_key)
    safe_remove(fallback_cert)

    # generate new ones
    print('server: generating fallback certificates')
    run_cmd([
        'openssl', 'req',
        '-x509',
        '-new',
        '-nodes',
        '-newkey', 'ec',
        '-pkeyopt', f'ec_paramgen_curve:{cfg.ec_curve}',
        '-keyout', fallback_key,
        '-out', fallback_cert,
        '-days', str(cfg.temporary_certs_expiration),
        '-subj', '/',
    ], err_msg='server: cannot create fallback certificate')
    os.chmod(fallback_key, 0o400)
    os.chmod(fallback_cert, 0o400)


class ValidationServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """
    IPv6 tcp server
    """
    daemon_threads = True
    address_family = socket.AF_INET6
    allow_reuse_address = True


class ValidationHandler(socketserver.BaseRequestHandler):
    """
    Request handler
    """

    def create_context(self, certfile, keyfile, fallback):
        """
        Create SSL context
        """
        # create SSL context
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.set_ciphers(cfg.server_ciphers)
        ssl_context.set_alpn_protocols(['acme-tls/1'])
        ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        try:
            ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            if fallback:
                ssl_context.set_servername_callback(self.load_certificate)
        except FileNotFoundError:
            print(f'server: missing certificates {keyfile} and {certfile}')

        return ssl_context


    def load_certificate(self, sslsocket, sni_name, sslcontext):
        """
        Load certificate for given SNI
        """
        # watchdog check
        if sni_name == '_':
            return

        # check SNI validity
        print(f'server: certificate request from {self.client_address[0]} for {sni_name}')
        if not re.match(r'^[-a-z0-9]{1,63}(\.[-a-z0-9]{1,63}){,3}$', sni_name, re.I):
            print('server: invalid sni name')
            return

        # compile certificate paths
        account_path = self.server.config['account_path']
        keyfile = os.path.join(account_path, cfg.challenges_path, sni_name, cfg.domain_key)
        certfile = os.path.join(account_path, cfg.challenges_path, sni_name, cfg.domain_cert)

        # create ssl context
        sslsocket.context = self.create_context(certfile, keyfile, fallback=False)


    def handle(self):
        """
        Handle incoming connection
        """
        # generate fallback self-signed certificate
        generate_fallback_certificates(self.server.config['fallback_key'], self.server.config['fallback_cert'])

        ssl_context = self.create_context(
            self.server.config['fallback_cert'],
            self.server.config['fallback_key'],
            fallback=True,
        )
        if ssl_context is not None:
            try:
                ssl_context.wrap_socket(self.request, server_side=True)
            except Exception as exc:
                print(f'server: {exc}')


def run_server(account_path, host, port, group, event_queue):
    """
    Run tls server for validation challenges
    """
    server = None
    try:
        fallback_key = os.path.join(account_path, cfg.fallback_key)
        fallback_cert = os.path.join(account_path, cfg.fallback_cert)

        # generate fallback certificates
        generate_fallback_certificates(fallback_key, fallback_cert)

        # create server
        server = ValidationServer((host, port), ValidationHandler)
        server.config = {
            'account_path': account_path,
            'host': host,
            'port': port,
            'fallback_key': fallback_key,
            'fallback_cert': fallback_cert,
        }

        # run challenge server
        print(f'server: running challenge server on {host} port {port}')
        server.serve_forever()
    except Exception:
        traceback.print_exc()
    except RuntimeError as exc:
        print(f'server: {exc}')
    except KeyboardInterrupt:
        print('server: exiting on user request', file=sys.stderr)
    finally:
        if server:
            server.shutdown()


# ==================
# validation process
# ==================


def send_request(url, data=None, err_msg='cannot send request', validate=True, check_status=True):
    """
    Make request, return json response, status code and headers
    """
    try:
        ctx = ssl.create_default_context()
        if not validate:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        response = urlopen(Request(
            url,
            data=data,
            headers={'Content-Type': 'application/jose+json', 'User-Agent': 'acme-tls'},
        ), context=ctx)
        response_data = response.read().decode('utf8')
        code = response.getcode()
        headers = response.headers
    except IOError as e:
        response_data = e.read().decode('utf8') if hasattr(e, 'read') else str(e)
        code = getattr(e, 'code', None)
        headers = {}
    try:
        response_data = json.loads(response_data) # try to parse json results
    except ValueError:
        pass # ignore json parsing errors

    if check_status and code not in [200, 201, 204]:
        detail = response_data['detail'] if isinstance(response_data, dict) else response_data
        raise RuntimeError(f'{err_msg}: status {code}, {detail}')

    return response_data, code, headers


def send_signed_request(url, payload, nonce_url, account_info, err_msg, validate=True):
    """
    Make signed request
    """
    attempts = 0
    max_attempts = 100

    # encode payload
    payload_b64 = '' if payload is None else b64(json.dumps(payload).encode('utf8'))

    # try request several times
    account_id = account_info['id']
    while attempts < max_attempts:
        # get new nonce
        new_nonce = send_request(nonce_url, validate=validate)[2]['Replay-Nonce']

        # create jws header
        header = {
            'url': url,
            'alg': account_info['alg'],
            'nonce': new_nonce,
        }
        header.update({'jwk': account_info['jwk']} if account_id is None else {'kid': account_id})
        header_b64 = b64(json.dumps(header).encode('utf8'))

        # sign header and payload
        protected_input = f'{header_b64}.{payload_b64}'.encode('utf8')
        der_signature = run_cmd(
            ['openssl', 'dgst', '-sha384', '-sign', account_info['path']],
            cmd_input=protected_input,
            err_msg=f'{err_msg}: cannot sign a request',
            )

        # parse DER signature
        # https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1/1797#1797
        roffset = 4
        rsize = der_signature[3]
        soffset = roffset + rsize + 2
        ssize = der_signature[soffset - 1]
        r = der_signature[roffset:roffset + rsize]
        s = der_signature[soffset:soffset + ssize]
        r = (48 * b'\x00' + r)[-48:]
        s = (48 * b'\x00' + s)[-48:]
        signature = r + s

        jws_json = json.dumps({
            'protected': header_b64,
            'payload': payload_b64,
            'signature': b64(signature),
        })

        # send request
        response, code, headers = send_request(url, data=jws_json.encode('utf8'), err_msg=err_msg, validate=validate, check_status=False)

        # check for errors
        if code == 400 and response['type'] == 'urn:ietf:params:acme:error:badNonce':
            # request new nonce
            continue
        elif code not in [200, 201, 204]:
            raise RuntimeError(f'{err_msg}: status {code}, {response["detail"]}')
        else:
            return response, code, headers

    raise RuntimeError(f'{err_msg}: too may failed request attempts')


def wait_for_completion(url, pending_statuses, nonce_url, account_info, err_msg, validate=True):
    """
    Wait for task completion
    """
    result = None
    polling_start = time.monotonic()
    while result is None or result['status'] in pending_statuses:
        # check timeout
        if (time.monotonic() - polling_start >= cfg.acme_polling_timeout):
            raise RuntimeError('polling status timed out')

        # sleep a bit
        if result is not None:
            time.sleep(2)

        # poll status
        result, _, _ = send_signed_request(
            url,
            None,
            nonce_url,
            account_info,
            err_msg,
            validate,
        )

    return result


def get_certificate(acme_directory, account_path, account_info, domains, group, renew, openssl_config, testing):
    """
    Get certificates through ACME process
    """
    print(f'getting certificate for {", ".join(domains)}')
    validate_acme = testing is None

    # get shortest domain as representative one
    main_domain = sorted(domains, key=len)[0]
    domain_key_name = os.path.join(account_path, cfg.certificates_path, main_domain, cfg.domain_key)
    domain_cert_name = os.path.join(account_path, cfg.certificates_path, main_domain, cfg.domain_cert)

    # check if all challenge certificates are in place
    print('  checking challenge certificates')
    challenge_certs = set()
    for domain in domains:
        challenge_key_name = os.path.join(account_path, cfg.challenges_path, domain, cfg.domain_key)
        challenge_cert_name = os.path.join(account_path, cfg.challenges_path, domain, cfg.domain_cert)
        try:
            expiration = get_certificate_expiration(challenge_cert_name)
            is_valid = expiration > datetime.now() + timedelta(days=cfg.validity_reserve)
            if is_valid and os.path.isfile(challenge_key_name):
                challenge_certs.add(domain)
        except FileNotFoundError:
            pass  # certificates were not generated yet
        except Exception as exc:
            print(f'cannot get expiration of {challenge_cert_name}, continuing anyway: {exc}')

    # check domain certificate validity
    if not renew and len(challenge_certs) == len(domains) and os.path.isfile(domain_cert_name):
        try:
            expiration = get_certificate_expiration(domain_cert_name)
            reserve = expiration - datetime.now()
            if reserve > timedelta(days=cfg.validity_reserve):
                # skip validation, it is not needed yet
                print(f'  certificate for {main_domain} does not need renewal, expiration in {reserve.days} days, skipping')
                return
        except (ValueError, OSError) as exc:
            print(f'  cannot parse current domain certificate date from {domain_cert_name}, continuing anyway: {exc}')

    # get domain private key
    try:
        # try to open private key file
        with open(domain_key_name):
            print('  using existing domain private key')
    except FileNotFoundError:
        # generate new private key
        domain_key_path = os.path.dirname(domain_key_name)
        print(f'  generating new domain private key to {domain_key_name}')
        os.makedirs(domain_key_path, exist_ok=True)
        with open(domain_key_name, 'wb') as domain_key_file:
            os.fchmod(domain_key_file.fileno(), 0o440)
            if group is not None:
                os.fchown(domain_key_file.fileno(), -1, grp.getgrnam(group).gr_gid)
            domain_key = run_cmd([
                'openssl', 'ecparam',
                '-name', cfg.ec_curve,
                '-genkey',
                '-noout'
            ], err_msg=f'cannot generate private key for {main_domain} to {domain_key_name}')
            domain_key_file.write(domain_key)

    # create a new order
    print('  creating new order')
    order_payload = {'identifiers': [{'type': 'dns', 'value': d} for d in domains]}
    order, _, order_headers = send_signed_request(
        acme_directory['newOrder'],
        order_payload,
        acme_directory['newNonce'],
        account_info,
        f'cannot create new order for {main_domain} at {acme_directory["newOrder"]}',
        validate_acme,
    )

    # get the authorizations that need to be completed
    for auth_url in order['authorizations']:
        # get authorization
        authorization, _, _ = send_signed_request(
            auth_url,
            None,
            acme_directory['newNonce'],
            account_info,
            f'cannot get validation challenges for {main_domain} at {auth_url}',
            validate_acme,
        )
        domain = authorization['identifier']['value']

        # skip if already valid
        if domain in challenge_certs and authorization['status'] == 'valid':
            print(f'   * {domain} already validated, skipping')
            continue

        print(f'   * {domain} validating')

        # find the tls-alpn-01 challenge token
        challenge = None
        for challenge in authorization['challenges']:
            if challenge['type'] == 'tls-alpn-01':
                break
        if challenge is None:
            raise RuntimeError('cannot find tls-alpn-01 validation challenge method')
        token = re.sub(r'[^A-Za-z0-9_\-]', '_', challenge['token'])

        # compute key authorization digest
        keyauthorization = f'{token}.{account_info["thumbprint"]}'.encode('utf8')
        digest = run_cmd([
                'openssl', 'dgst',
                '-sha256',
                '-c',
                '-hex',
            ],
            cmd_input=keyauthorization,
            err_msg=f'cannot compute key authorization digest for {domain}',
        )
        acme_validation = digest.split()[1].decode('utf8')

        # challenge certificate paths
        os.makedirs(os.path.join(account_path, cfg.challenges_path, domain), exist_ok=True)
        challenge_key_name = os.path.join(account_path, cfg.challenges_path, domain, cfg.domain_key)
        challenge_cert_name = os.path.join(account_path, cfg.challenges_path, domain, cfg.domain_cert)
        original_key_name = challenge_key_name + '.original'
        original_cert_name = challenge_cert_name + '.original'

        # generate validation challenge certificate
        with tempfile.NamedTemporaryFile(mode='w') as openssl_config_file:
            # update default openssl config
            openssl_config_file.write(openssl_config)
            openssl_config_file.write(f'\n[SAN]\nsubjectAltName=DNS:{domain}\n1.3.6.1.5.5.7.1.31=critical,DER:04:20:{acme_validation}\n')
            openssl_config_file.flush()

            # backup original validation certificates
            print(f'   * {domain} backing up original validation certificates')
            try:
                os.rename(challenge_key_name, original_key_name)
                os.rename(challenge_cert_name, original_cert_name)
            except FileNotFoundError:
                pass  # certificates were not generated yet

            try:
                # create certificate
                run_cmd([
                    'openssl', 'req',
                    '-x509',
                    '-new',
                    '-nodes',
                    '-newkey', 'ec',
                    '-pkeyopt', f'ec_paramgen_curve:{cfg.ec_curve}',
                    '-keyout', challenge_key_name,
                    '-out', challenge_cert_name,
                    '-subj', '/',
                    '-days', str(cfg.temporary_certs_expiration),
                    '-extensions', 'SAN',
                    '-config', openssl_config_file.name,
                ], err_msg=f'cannot create validation certificates {challenge_key_name} and {challenge_cert_name}')
                os.chmod(challenge_key_name, 0o400)
                os.chmod(challenge_cert_name, 0o400)

                # check validation server
                print(f'   * {domain} checking validation server')
                check_attempts = 3
                while check_attempts > 0:
                    try:
                        if testing is None:
                            # send request to domain being validated
                            check_server(domain, 443)
                        else:
                            # send request to test server
                            check_server(testing[0], testing[1])
                        break
                    except CheckError as exc:
                        print(f'  validation server check for {domain} failed: {exc}')
                        raise
                        check_attempts -= 1
                        if check_attempts == 0:
                            raise RuntimeError('  cannot reach validation server, skipping')
                        time.sleep(3)

                # send that validation is prepared
                print(f'   * {domain} ready to be validated')
                send_signed_request(
                    challenge['url'],
                    {},
                    acme_directory['newNonce'],
                    account_info,
                    f'cannot submit validation challenge for {domain} at {challenge["url"],}',
                    validate_acme,
                )

                # wait for validation to be completed
                authorization = wait_for_completion(
                    auth_url,
                    ['pending'],
                    acme_directory['newNonce'],
                    account_info,
                    f'cannot check challenge status for {domain} at {auth_url}',
                    validate_acme,
                )
                if authorization['status'] != 'valid':
                    raise RuntimeError(f'validation challenge did not pass for {domain}: {authorization}')
                print(f'   * {domain} successfully validated')
            except:
                print(f'   * {domain} reverting to original challenge certificates')
                raise

            # move validation challenge certificates to final place
            print(f'   * {domain} cleaning old challenge certificates')
            try:
                os.unlink(original_key_name)
                os.unlink(original_cert_name)
            except FileNotFoundError:
                pass  # certificates were not generated previously

        print(f'   * {domain} done')

    # generate domain certificate request
    alt_names = ','.join(f'DNS:{domain}' for domain in domains)
    domain_csr_der = run_cmd([
        'openssl', 'req',
        '-new',
        '-sha256',
        '-key', domain_key_name,
        '-subj', '/',
        '-addext', f'subjectAltName={alt_names}',
        '-outform', 'DER',
    ], err_msg=f'cannot generate certificate request for {main_domain} to {domain_key_name}')

    # finalize the order with the csr
    print('  signing domain certificate')
    send_signed_request(
        order['finalize'],
        {'csr': b64(domain_csr_der)},
        acme_directory['newNonce'],
        account_info,
        f'cannot finalize order for {main_domain} at {order["finalize"]}',
        validate_acme,
    )

    # wait for order to be done
    order = wait_for_completion(
        order_headers['Location'],
        ['pending', 'processing'],
        acme_directory['newNonce'],
        account_info,
        f'cannot check order status for {main_domain} at {order_headers["Location"]}',
        validate_acme,
    )
    if order['status'] != 'valid':
        raise RuntimeError(f'order for {main_domain} failed: {order}')

    # download domain certificate
    print('  downloading domain certificate')
    domain_cert, _, _ = send_signed_request(
        order['certificate'],
        None,
        acme_directory['newNonce'],
        account_info,
        f'cannot download certificate for {main_domain} from {order["certificate"]}',
        validate_acme,
    )

    # save domain certificate
    print('  saving domain certificate')
    domain_cert_tmp = domain_cert_name + '.tmp'
    try:
        with open(domain_cert_tmp, 'w') as domain_cert_file:
            os.fchmod(domain_cert_file.fileno(), 0o440)
            if group is not None:
                os.fchown(domain_cert_file.fileno(), -1, grp.getgrnam(group).gr_gid)
            domain_cert_file.write(domain_cert)
        os.rename(domain_cert_tmp, domain_cert_name)
        print(f'  domain certificate saved to {domain_cert_name}')
    finally:
        try:
            os.unlink(domain_cert_tmp)
        except FileNotFoundError:
            pass  # probably already renamed


def run_validation(account_path, acme_url, domains, contact, group, renew, event_queue, testing):
    """
    Run complete certificate retrieval for one account
    """
    try:
        print('validation started')
        validated = 0
        validate_acme = testing is None

        # get openssl config for validation certificate
        openssl_info = run_cmd(
            ['openssl', 'version', '-d'],
            err_msg='cannot get openssl configuration path',
        )
        openssl_config_dir = openssl_info.strip().split(b' ')[1][1:-1].decode('utf8')
        openssl_config_file_name = os.path.join(openssl_config_dir, 'openssl.cnf')
        with open(openssl_config_file_name) as openssl_config_file:
            openssl_config = openssl_config_file.read()

        print('parsing account key')
        account_key_path = os.path.join(account_path, cfg.account_key_name)

        # check ec certificate
        cert_header = b'-----BEGIN EC PRIVATE KEY-----'
        with open(account_key_path, 'rb') as account_key_file:
            file_header = account_key_file.read(len(cert_header))
        if file_header != cert_header:
            raise RuntimeError(f'expecting account key as elliptic curve private key in {account_key_path}')

        # parse account key
        key_info = run_cmd([
            'openssl', 'ec', '-in', account_key_path, '-noout', '-text'
        ], err_msg=f'cannot parse account key in {account_key_path}').decode('utf8')
        serialized_key = re.search(r'pub:\n((?:\s+[:0-9a-f]+\n)+)', key_info, re.I).group(1)
        serialized_key = binascii.unhexlify(re.sub(r'[:\s]', '', serialized_key))
        compression = serialized_key[0]
        if compression != 4:
            raise RuntimeError('only uncompressed public key is supported, found compressed one in {account_key_path}')
        public_key = serialized_key[1:]
        curve_name = re.search(r'ASN1 OID: (\w+)', key_info).group(1)
        if curve_name != cfg.ec_curve:
            raise RuntimeError(f'only {cfg.ec_curve} is supported, found {curve_name} in {account_key_path}')
        x = public_key[:48]
        y = public_key[48:]

        # create jwk and signing information
        jwk = {
            'kty': 'EC',
            'crv': 'P-384',
            'x': b64(x),
            'y': b64(y),
        }
        key = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
        account_info = {
            'alg': 'ES384',
            'jwk': jwk,
            'path': account_key_path,
            'thumbprint': b64(hashlib.sha256(key.encode('utf8')).digest()),
        }

        # get the ACME directory of urls
        print('getting ACME directory')
        acme_directory, _, _ = send_request(acme_url, err_msg=f'cannot fetch acme directory url {acme_url}', validate=validate_acme)

        # create account
        print('registering account')
        register_payload = {'termsOfServiceAgreed': True}
        account_info['id'] = None
        _, code, headers = send_signed_request(
            acme_directory['newAccount'],
            register_payload,
            acme_directory['newNonce'],
            account_info,
            f'cannot register account at {acme_directory["newAccount"]}',
            validate_acme,
        )
        account_info['id'] = headers['Location']
        print('{0} account id: {1}'.format('registered' if code == 201 else 'already registered', account_info['id']))

        # update account contact
        if contact:
            update_payload = {'contact': contact}
            account, _, _ = send_signed_request(
                account_info['id'],
                update_payload,
                acme_directory['newNonce'],
                account_info,
                f'cannot update account contact details at {account_info["id"]}',
                validate_acme,
            )
            print(f'updated contact details with {", ".join(account["contact"])}')

        # get certificates
        for domain_names in domains:
            try:
                get_certificate(
                    acme_directory,
                    account_path,
                    account_info,
                    domain_names,
                    group,
                    renew,
                    openssl_config,
                    testing,
                )
                validated += 1
            except RuntimeError as exc:
                print(exc)
                continue
            except Exception:
                traceback.print_exc()
                continue

        print('validation done')
        event_queue.put('validation_done')
    except RuntimeError as exc:
        print(exc)
        sys.exit(1)
    except Exception:
        traceback.print_exc()
        sys.exit(3)
    except KeyboardInterrupt:
        print('exiting on user request')

    sys.exit(0 if validated == len(domains) else 1)


# ================
# watchdog process
# ================


def next_schedule(hour):
    """
    Compute next time schedule
    """
    if hour is not None:
        now = datetime.now()
        scheduled = now.replace(
            hour=hour,
            minute=random.randint(0, 59),
            second=random.randint(0, 59),
            microsecond=0,
        )
        if scheduled < now + timedelta(hours=1):
            scheduled += timedelta(days=1)

        return scheduled
    else:
        return None


def event_listener(queue, done_cmd):
    """
    Listen to applicaition events
    """
    while True:
        event = queue.get()
        if event == 'validation_done':
            # run done command
            if done_cmd:
                print(f'watchdog: running user command: {done_cmd}')
                subprocess.run(done_cmd, shell=True)
        else:
            assert False


def check_account_path(path):
    """
    Initial account directory check
    """
    try:
        check_file_name = os.path.join(path, cfg.check_file)
        with open(check_file_name, 'wb') as check_file:
            check_file.write(b'ok')
    except Exception as exc:
        raise CheckError(f'cannot access {path} for writing, aborting: {exc}')
    finally:
        try:
            os.unlink(check_file_name)
        except:
            pass  # nothing more to do about it


def check_account_key(path, create):
    """
    Initial account key check
    """
    try:
        # try to open account key
        with open(path, 'rb') as account_key_file:
            pass
    except FileNotFoundError:
        # create new key if requested
        if create:
            print('watchdog: account key not found, generating new one')
            with open(path, 'wb') as account_key_file:
                account_key = run_cmd([
                    'openssl', 'ecparam',
                    '-name', cfg.ec_curve,
                    '-genkey',
                    '-noout'
                ], err_msg='cannot create account key')
                account_key_file.write(account_key)
                os.fchmod(account_key_file.fileno(), 0o400)
            print(f'watchdog: new account key saved to {path}')
        else:
            raise CheckError(f'account key not found at {path}, quitting')
    except Exception as exc:
        raise CheckError(f'cannot open account key at {path}, quitting: {exc}')


def check_domains_list(path):
    """
    Initial domain list check
    """
    try:
        domains = []
        with open(path) as domains_file:
            for line in domains_file:
                line = line.strip()

                # ignore comments
                if line.startswith('#'):
                    continue

                # split subdomains
                domain_names = []
                for name in cfg.domain_separator.split(line):
                    name = name.strip()
                    if not name.strip():
                        continue
                    if name.startswith('#'):
                        break
                    domain_names.append(name)

                # add domains to the list
                if domain_names:
                    domains.append(domain_names)

        if not domains:
            raise CheckError('domains list is empty, add at least one domain')

        print('watchdog: found domains')
        for names in domains:
            print(f'  {", ".join(names)}')

        return domains
    except FileNotFoundError:
        raise CheckError(f'cannot find domains list at {path}')


def run_watchdog(args):
    """
    Run watchdog
    """
    # setup signaling
    hup_event = Event()
    signal.signal(signal.SIGHUP, lambda sig, frame: hup_event.set())

    # run server watchdog and validation checker
    server_pid = None
    validation_pid = None
    try:
        # check account directory
        print('watchdog: checking account directory')
        check_account_path(args.path)
        domains = check_domains_list(os.path.join(args.path, cfg.domains_list_name))
        check_account_key(os.path.join(args.path, cfg.account_key_name), args.new_account_key)

        # run thread listening for events
        event_queue = Queue()
        event_thread = threading.Thread(target=event_listener, args=(event_queue, args.done_cmd), daemon=True)
        event_thread.start()

        print('watchdog: starting validation server')
        server_process = Process(target=run_server, args=(
            args.path,
            args.host,
            args.port,
            args.group,
            event_queue,
        ), daemon=True)
        server_process.start()
        server_pid = server_process.pid

        # wait for server to come up
        check_attempts = 5
        while check_attempts > 0:
            try:
                check_server(args.host, args.port)
                break
            except CheckError as exc:
                check_attempts -= 1
                if check_attempts == 0:
                    raise RuntimeError(f'watchdog: cannot reach server, quitting: {exc}')
                time.sleep(1)

        first_schedule = True
        while True:
            # compute next schedule
            if args.schedule in ('once', 'force') and first_schedule:
                scheduled = datetime.now().replace(microsecond=0) - timedelta(days=1)
            else:
                scheduled = next_schedule(args.schedule)
            first_schedule = False

            # wait for schedule
            if scheduled is None:
                print('watchdog: waiting for hup signal')
            else:
                print(f'watchdog: next schedule is at {scheduled}')
            hup_event.clear()
            while not hup_event.is_set():
                # check server
                if server_pid is not None:
                    try:
                        check_server(args.host, args.port)
                    except CheckError as exc:
                        print(f'watchdog: cannot reach server, stopping it: {exc}')
                        safe_kill(server_pid)
                        server_pid = None

                # run server if not running
                if server_pid is None or not check_pid(server_pid):
                    print('watchdog: starting server')
                    server_process = Process(target=run_server, args=(
                        args.path,
                        args.host,
                        args.port,
                        args.group,
                        event_queue,
                    ), daemon=True)
                    server_process.start()
                    server_pid = server_process.pid

                    # wait for server to come up
                    check_attempts = 5
                    while check_attempts > 0:
                        try:
                            check_server(args.host, args.port)
                            break
                        except CheckError as exc:
                            check_attempts -= 1
                            if check_attempts == 0:
                                print(f'watchdog: cannot reach server, continuing anyway: {exc}')
                            time.sleep(1)

                # check time schedule
                if scheduled is not None and datetime.now() >= scheduled:
                    break

                # wait a minute for next batch of checks
                hup_event.wait(cfg.server_polling_timeout)

            # reload domain list on hup signal
            if hup_event.is_set():
                print('watchdog: reloading domains list requested by hup signal')
                try:
                    domains = check_domains_list(os.path.join(args.path, cfg.domains_list_name))
                except CheckError as exc:
                    print(f'watchdog: failed to reload domains list, keeping old one: {exc}')

            # kill validation if still running
            safe_kill(validation_pid)
            validation_pid = None

            # run validation
            validation_process = Process(target=run_validation, args=(
                args.path,
                args.acme,
                domains,
                args.contact,
                args.group,
                args.schedule == 'force',
                event_queue,
                (args.host, args.port) if args.testing else None,
            ), daemon=True)
            validation_process.start()
            validation_pid = validation_process.pid

            # quit when only one validation was requested
            if args.schedule in ('once', 'force'):
                validation_process.join()
                print('watchdog: quitting, scheduled only once')
                return validation_process.exitcode
    except RuntimeError as exc:
        print(f'watchdog: {exc}')
        return 1
    except Exception:
        traceback.print_exc()
        return 3
    except KeyboardInterrupt:
        print('watchdog: exiting on user request')
        return 0
    finally:
        # kill running processes
        safe_kill(validation_pid)
        safe_kill(server_pid)


def main():
    """
    Start server and monitor certificates
    """
    def schedule(string):
        """
        parse schedule argument
        """
        if string in ('once', 'force'):
            return string
        else:
            hour = int(string)
            if 0 <= hour < 24:
                return hour
            else:
                raise ValueError()

    def ca(string):
        """
        Parse acme argument
        """
        if string.lower() in cfg.acme_directories:
            return cfg.acme_directories[string.lower()]

        parsed = urlparse(string)
        if parsed.scheme != 'https':
            raise ValueError()

        return string

    # parse script arguments
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    parser.add_argument('--path', metavar='account_dir', required=True, help='path to account directory with certificates')
    parser.add_argument('--acme', metavar='ca', required=True, type=ca, help='certificate authority name or ACME url')
    parser.add_argument('--contact', metavar='contact', nargs='*', help='update account contact information')
    parser.add_argument('--new-account-key', action='store_true', default=False, help='create new account key if does not exist')
    parser.add_argument('--host', metavar='host', default='::1', help='validation server hostname, by default ::1')
    parser.add_argument('--port', metavar='port', default=7443, type=int, help='validation server port, by default 7443')
    parser.add_argument('--group', metavar='group', default=None, help='validation and domain certificates user group')
    parser.add_argument('--schedule', metavar='schedule', default='4', type=schedule, help='when to schedule certificate check (hour | once | force), by default 4')
    parser.add_argument('--done-cmd', metavar='cmd', default=None, help='command to run after certificates validation is done')
    parser.add_argument('--testing', action='store_true', default=False, help=argparse.SUPPRESS)
    args = parser.parse_args()

    # run watchdog
    return run_watchdog(args)


# entrypoint
if __name__ == '__main__':
    sys.exit(main())
