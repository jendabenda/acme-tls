#!/usr/bin/env python3
"""
acme-tls obtains and automatically renews domain certificates using acme tls-alpn-01 protocol and elliptic curve cryptography.

usage:
  acme-tls new-account account_path
  acme-tls update-account account_path
  acme-tls deactivate-account account_path
  acme-tls run account_path
  acme-tls renew account_path --domain domain ... [--force]
  acme-tls renew-all account_path [--force]
  acme-tls revoke account_path --domain domain ...
  acme-tls revoke-all account_path
  acme-tls version

  all commands accept --help to show detailed usage information

quick guide:
  mkdir account_path
  cat > account_path/config         # paste configuration
  cat > account_path/domains.list   # paste domains
  acme-tls new-account account_path # create new account
  acme-tls run account_path         # obtain certificates, monitor and renew if necessary
  # domain certificates are stored in acount/certificates

example account/config:
  acme = letsencrypt  # acme certificate authority, i.e. letsencrypt,
                      # letsencrypt_test or acme directory url
  contact =     # contact information for certificate authority, i.e. user@example.org, optional
  host = ::1    # validation server hostname
  port = 7443   # validation server port
  group =       # user group for generated certificates, i.e. www-data, optional
  schedule = 4  # hour which acme-tls tries to check and renew domain certificates, optional
  done_cmd =    # command to be run after successful batch with new domain certificates, optional

example account/domain.list:
  example.org
  example.net subdomain.example.net another.example.net  # multidomain certificate

author: Jan Prochazka
license: none, public domain
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
import errno
from datetime import datetime, timedelta
from threading import Event
from multiprocessing import Process, Queue
from urllib.request import urlopen, Request
from urllib.parse import urlparse


class cfg:
    """
    Server configuration
    """
    # acme-tls version
    version = '1.1'

    # server ciphers
    server_ciphers = ('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256')

    # prepared acme directory urls
    acme_directories = {
        'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
        'letsencrypt_test': 'https://acme-staging-v02.api.letsencrypt.org/directory',
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

    # domain regexes
    domain_separator = re.compile(r'[ ,\t]')
    domain_validation = re.compile(r'^[-a-z0-9]{1,63}(\.[-a-z0-9]{1,63}){,8}$', re.I)

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
    ], err_msg='cannot create fallback certificate')
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
        if cfg.domain_validation.match(sni_name) is None:
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


def run_server(account_path, config, event_queue):
    """
    Run tls server for validation challenges
    """
    host = config['host']
    port = config['port']

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
        print(f'server: running validation server on {host} port {port}')
        server.serve_forever()
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            print(f'server: address {host} port {port} is already in use, quitting')
        else:
            traceback.print_exc()
    except RuntimeError as exc:
        print(f'server: {exc}')
    except Exception:
        traceback.print_exc()
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


def send_signed_request(url, payload, account_info, err_msg, validate=True):
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
        new_nonce = send_request(account_info['acme_directory']['newNonce'], validate=validate)[2]['Replay-Nonce']

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
            ['openssl', 'dgst', '-sha384', '-sign', account_info['account_key_path']],
            cmd_input=protected_input,
            err_msg=f'{err_msg}: cannot sign a request',
            )

        # parse DER signature
        # https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1/1797#1797
        key_size = account_info['account_key_size']
        roffset = 4
        rsize = der_signature[3]
        soffset = roffset + rsize + 2
        ssize = der_signature[soffset - 1]
        r = der_signature[roffset:roffset + rsize]
        s = der_signature[soffset:soffset + ssize]
        r = (key_size * b'\x00' + r)[-key_size:]
        s = (key_size * b'\x00' + s)[-key_size:]
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


def wait_for_completion(url, pending_statuses, account_info, err_msg, validate=True):
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
            account_info,
            err_msg,
            validate,
        )

    return result


def get_certificate(account_path, config, account_info, domains, renew, openssl_config, testing):
    """
    Get certificates through ACME process
    """
    acme_directory = account_info['acme_directory']
    group = config.get('group')

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
                return False
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
                    account_info,
                    f'cannot submit validation challenge for {domain} at {challenge["url"],}',
                    validate_acme,
                )

                # wait for validation to be completed
                authorization = wait_for_completion(
                    auth_url,
                    ['pending'],
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
        account_info,
        f'cannot finalize order for {main_domain} at {order["finalize"]}',
        validate_acme,
    )

    # wait for order to be done
    order = wait_for_completion(
        order_headers['Location'],
        ['pending', 'processing'],
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

    return True  # new certificate was issued


def run_validation(account_path, config, domains, renew, event_queue, testing):
    """
    Run complete certificate retrieval for one account
    """
    try:
        print('validation started')
        validated = 0
        issued = 0

        # get openssl config for validation certificate
        openssl_info = run_cmd(
            ['openssl', 'version', '-d'],
            err_msg='cannot get openssl configuration path',
        )
        openssl_config_dir = openssl_info.strip().split(b' ')[1][1:-1].decode('utf8')
        openssl_config_file_name = os.path.join(openssl_config_dir, 'openssl.cnf')
        with open(openssl_config_file_name) as openssl_config_file:
            openssl_config = openssl_config_file.read()

        # connect to account
        account_info = connect_account(account_path, config, True, testing)

        # get certificates
        for domain_names in domains:
            try:
                issued += int(get_certificate(
                    account_path,
                    config,
                    account_info,
                    domain_names,
                    renew,
                    openssl_config,
                    testing,
                ))
                validated += 1
            except RuntimeError as exc:
                print(exc)
                continue
            except Exception:
                traceback.print_exc()
                continue

        print('validation done')
        event_queue.put(('validation_done', issued))
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


def event_listener(account_path, config, queue):
    """
    Listen to applicaition events
    """
    done_cmd = config.get('done_cmd')

    while True:
        event, data = queue.get()
        if event == 'validation_done':
            # run done command
            if done_cmd:
                issued = data
                if issued > 0:
                    print(f'watchdog: running user command: {done_cmd}')
                    try:
                        sys.stdout.flush()
                        subprocess.run(done_cmd, cwd=account_path, shell=True)
                    except Exception:
                        print('watchdog: cannot run user command: {done_cmd}')
                        traceback.print_exc()
                else:
                    print('watchdog: no new certificates were issued, not running done callback')

        else:
            assert False


def check_account_path(path):
    """
    Initial account directory check
    """
    if not os.path.isdir(path):
        raise CheckError(f'account directory {path} does not exist')


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
            raise CheckError(f'account key not found at {path}')
    except Exception as exc:
        raise CheckError(f'cannot open account key at {path}: {exc}')


def read_domains_list(path):
    """
    Read domains list
    """
    try:
        domains = []
        with open(path) as domains_file:
            for line_number, line in enumerate(domains_file, 1):
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
                    if cfg.domain_validation.match(name) is None:
                        raise CheckError(f'domain name {name} is invalid, found at {path}:{line_number}')
                    domain_names.append(name)

                # add domains to the list
                if domain_names:
                    domains.append(domain_names)

        if not domains:
            raise CheckError('domains list is empty, add at least one domain')

        print('found domains')
        for names in domains:
            print(f'  {", ".join(names)}')

        return domains
    except FileNotFoundError:
        raise CheckError(f'cannot find domains list at {path}')


def connect_account(account_path, config, existing_only, testing):
    """
    Log in to account, return account information
    """
    acme_url = config['acme']
    contact = config.get('contact')
    validate_acme = testing is None

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
    key_size = 384 // 8  # secp384r1
    x = public_key[:key_size]
    y = public_key[key_size:]

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
        'thumbprint': b64(hashlib.sha256(key.encode('utf8')).digest()),
        'account_key_path': account_key_path,
        'account_key_size': key_size,
    }

    # get the ACME directory of urls
    print('getting ACME directory')
    acme_directory, _, _ = send_request(acme_url, err_msg=f'cannot fetch acme directory url {acme_url}', validate=validate_acme)
    account_info['acme_directory'] = acme_directory

    # create account
    print('registering account')
    register_payload = {
        'onlyReturnExisting': existing_only,
        'termsOfServiceAgreed': True,
    }
    account_info['id'] = None
    _, code, headers = send_signed_request(
        acme_directory['newAccount'],
        register_payload,
        account_info,
        f'cannot register account at {acme_directory["newAccount"]}',
        validate_acme,
    )
    account_info['id'] = headers['Location']
    print('{} account id: {}'.format('registered' if code == 201 else 'already registered', account_info['id']))

    # update account contact
    if contact is not None:
        update_payload = {'contact': contact}
        account, _, _ = send_signed_request(
            account_info['id'],
            update_payload,
            account_info,
            f'cannot update account contact details at {account_info["id"]}',
            validate_acme,
        )
        print(f'updated contact details with {", ".join(account["contact"])}')

    return account_info


def run_new_account(account_path, config, testing):
    """
    Create new acme account
    """
    check_account_key(os.path.join(account_path, cfg.account_key_name), create=True)
    connect_account(account_path, config, False, testing)
    return 0


def run_update_account(account_path, config, testing):
    """
    Update acme account
    """
    check_account_key(os.path.join(account_path, cfg.account_key_name), create=False)
    connect_account(account_path, config, True, testing)
    return 0


def run_deactivate_account(account_path, config, testing):
    """
    Deactivate acme acccount
    """
    validate_acme = not testing

    # connect to account
    check_account_key(os.path.join(account_path, cfg.account_key_name), create=False)
    account_info = connect_account(account_path, config, True, testing)

    # deactivate account
    deactivate_payload = {'status': 'deactivated'}
    account, _, _ = send_signed_request(
        account_info['id'],
        deactivate_payload,
        account_info,
        f'cannot deactivate account at {account_info["id"]}',
        validate_acme,
    )
    print(f'account {account_info["id"]} is deactivated')
    return 0


def run_watchdog(account_path, config, domains_list, schedule_once, testing):
    """
    Run watchdog
    """
    server_host = config['host']
    server_port  = config['port']
    schedule  = config.get('schedule') if schedule_once is None else schedule_once

    # setup signaling
    hup_event = Event()
    signal.signal(signal.SIGHUP, lambda sig, frame: hup_event.set())

    # run server watchdog and validation checker
    server_pid = None
    validation_pid = None
    try:
        # run thread listening for events
        event_queue = Queue()
        event_thread = threading.Thread(target=event_listener, args=(account_path, config, event_queue), daemon=True)
        event_thread.start()

        print('watchdog: starting validation server')
        server_process = Process(target=run_server, args=(
            account_path,
            config,
            event_queue,
        ), daemon=True)
        server_process.start()
        server_pid = server_process.pid

        # wait for server to come up
        check_attempts = 5
        while check_attempts > 0:
            try:
                check_server(server_host, server_port)
                break
            except CheckError as exc:
                check_attempts -= 1
                if check_attempts == 0:
                    raise RuntimeError(f'watchdog: cannot reach server, quitting: {exc}')
                time.sleep(1)

        first_schedule = True
        while True:
            # compute next schedule
            if schedule in ('once', 'force') and first_schedule:
                scheduled = datetime.now().replace(microsecond=0) - timedelta(days=1)
            else:  # can miss schedule on hup, certs have been renewed anyway
                scheduled = next_schedule(schedule)
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
                        check_server(server_host, server_port)
                    except CheckError as exc:
                        print(f'watchdog: cannot reach server, stopping it: {exc}')
                        safe_kill(server_pid)
                        server_pid = None

                # run server if not running
                if server_pid is None or not check_pid(server_pid):
                    print('watchdog: starting validation server')
                    server_process = Process(target=run_server, args=(
                        account_path,
                        config,
                        event_queue,
                    ), daemon=True)
                    server_process.start()
                    server_pid = server_process.pid

                    # wait for server to come up
                    check_attempts = 5
                    while check_attempts > 0:
                        try:
                            check_server(server_host, server_port)
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
            if schedule not in ('once', 'force') and hup_event.is_set():
                print('watchdog: reloading domains list requested by hup signal')
                try:
                    domains_list = read_domains_list(os.path.join(account_path, cfg.domains_list_name))
                except CheckError as exc:
                    print(f'watchdog: failed to reload domains list, keeping old one: {exc}')

            # kill validation if still running
            safe_kill(validation_pid)
            validation_pid = None

            # run validation
            validation_process = Process(target=run_validation, args=(
                account_path,
                config,
                domains_list,
                schedule == 'force',
                event_queue,
                (server_host, server_port) if testing else None,
            ), daemon=True)
            validation_process.start()
            validation_pid = validation_process.pid

            # quit when only one validation was requested
            if schedule in ('once', 'force'):
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


def filter_domains(domains, domains_list, domains_list_path):
    """
    Filter domains from domains list
    """
    main_domains = {sorted(subdomains, key=len)[0]: subdomains for subdomains in domains_list}
    included_domains_list = []
    for domain in domains:
        if domain in main_domains:
            included_domains_list.append(main_domains[domain])
        else:
            raise RuntimeError(f'domain {domain} is not included in {domains_list_path}')

    return included_domains_list


def run_renew(account_path, config, domains, force, testing):
    """
    Renew seleced domains
    """
    # connect to account
    check_account_key(os.path.join(account_path, cfg.account_key_name), create=False)
    connect_account(account_path, config, True, testing)
    domains_list = read_domains_list(os.path.join(account_path, cfg.domains_list_name))

    # filter domains
    included_domains_list = filter_domains(domains, domains_list, os.path.join(account_path, cfg.domains_list_name))

    # run renewal
    run_watchdog(account_path, config, included_domains_list, 'force' if force else 'once', testing)


def revoke_certificates(account_path, config, account_info, domains_list, testing):
    """
    Revoke certificates with account id
    """
    validate_acme = not testing

    revoked = 0
    acme_directory = account_info['acme_directory']
    for subdomains in domains_list:
        try:
            main_domain = sorted(subdomains, key=len)[0]

            # get certificate in DER format
            certificate_path = os.path.join(account_path, cfg.certificates_path, main_domain, cfg.domain_cert)
            if not os.path.exists(certificate_path):
                print(f'missing certificate for {main_domain}, skipping')
                continue

            certificate = run_cmd([
                'openssl', 'x509',
                '-in', certificate_path,
                '-outform', 'DER',
            ], err_msg=f'cannot read certificate from {certificate_path}')

            # request revocation
            revocation_payload = {'certificate': b64(certificate)}
            account_id = account_info['id']
            account, _, _ = send_signed_request(
                acme_directory['revokeCert'],
                revocation_payload,
                account_info,
                f'cannot revoke certificate for {main_domain} from acount {account_id}',
                validate_acme,
            )

            revoked += 1
        except RuntimeError as exc:
            print(exc)
        except Exception:
            traceback.print_exc()

    return 0 if revoked == len(domains_list) else 1


def run_revoke(account_path, config, domains, testing):
    """
    Revoke selected domains
    """
    # connect to account
    check_account_key(os.path.join(account_path, cfg.account_key_name), create=False)
    account_info = connect_account(account_path, config, True, testing)
    domains_list = read_domains_list(os.path.join(account_path, cfg.domains_list_name))

    # filter domains
    included_domains_list = filter_domains(domains, domains_list, os.path.join(account_path, cfg.domains_list_name))

    return revoke_certificates(account_path, config, account_info, included_domains_list, testing)


def run_renew_all(account_path, config, force, testing):
    """
    Renew all domains
    """
    # connect to account
    check_account_key(os.path.join(account_path, cfg.account_key_name), create=False)
    connect_account(account_path, config, True, testing)
    domains_list = read_domains_list(os.path.join(account_path, cfg.domains_list_name))

    # run renewal
    run_watchdog(account_path, config, domains_list, 'force' if force else 'once', testing)


def run_revoke_all(account_path, config, testing):
    """
    Renew selected domains
    """
    # connect to account
    check_account_key(os.path.join(account_path, cfg.account_key_name), create=False)
    account_info = connect_account(account_path, config, True, testing)
    domains_list = read_domains_list(os.path.join(account_path, cfg.domains_list_name))

    return revoke_certificates(account_path, config, account_info, domains_list, testing)


def run_auto(account_path, config, testing):
    """
    Renew all domains and monitor them
    """
    # connect to account
    check_account_key(os.path.join(account_path, cfg.account_key_name), create=False)
    connect_account(account_path, config, True, testing)
    domains_list = read_domains_list(os.path.join(account_path, cfg.domains_list_name))

    # run renewal
    run_watchdog(account_path, config, domains_list, None, testing)


def read_config(path):
    """
    Reads acme-tls configuration
    """
    def parse_port(value):
        msg = 'port number must be a number between 1 and 65535'
        try:
            value = int(value)
        except ValueError:
            raise ValueError(msg)

        if not (0 < value < 65536):
            raise ValueError(msg)
        else:
            return value

    def parse_acme(value):
        msg = f'acme can be either one of {", ".join(cfg.acme_directories)} or can be https url pointing to acme directory'
        if value in cfg.acme_directories:
            return cfg.acme_directories[value]
        else:
            try:
                parsed = urlparse(value)
            except ValueError:
                raise ValueError(msg)

            if parsed.scheme != 'https':
                raise ValueError(msg)
            else:
                return value

    def parse_schedule(value):
        msg = 'schedule hour muste be a number between 0 and 23'
        try:
            value = int(value)
        except ValueError:
            raise ValueError(msg)

        if not (0 <= value < 24):
            raise ValueError(msg)
        else:
            return value

    def parse_contact(value):
        contact = []
        for part in value.split(' '):
            part = part.strip()
            if part:
                contact.append(part)

        return contact if contact else None

    mandatory = set('acme host port'.split())
    optional = set('contact group schedule done_cmd'.split())
    parsers = {
        'acme': parse_acme,
        'port': parse_port,
        'schedule': parse_schedule,
        'contact': parse_contact,
    }

    try:
        # read config
        config = {}
        with open(path) as config_file:
            for line_num, line in enumerate(config_file, 1):
                line = line.strip()

                # ignore comments
                if line.startswith('#') or not line:
                    continue

                # parse line
                line = line.split('#', 1)[0]
                key_value = line.split('=', 2)
                if len(key_value) != 2:
                    raise RuntimeError(f'missing = in {path}:{line_num}')
                key, value = key_value
                key = key.strip()
                value = value.strip()
                if key not in mandatory and key not in optional:
                    raise RuntimeError(f'unknown option {key} in {path}:{line_num}')

                value = value.strip()
                if value:
                    try:
                        config[key] = parsers[key](value) if key in parsers else value
                    except ValueError as exc:
                        raise RuntimeError(f'incorrect option in {path}: {exc}')

        # check mandatory keys
        missing = mandatory - config.keys()
        if missing:
            raise RuntimeError(f'missing {", ".join(missing)} options in {path}')

        return config
    except FileNotFoundError:
        raise RuntimeError(f'cannot find {path}')
    except IOError as exc:
        raise RuntimeError(f'cannot read {path}: {exc}')


def check_openssl():
    """
    Check for openssl binary
    """
    run_cmd(['openssl', 'version'], err_msg='cannot find openssl binary, do you have it installed?')


def main():
    """
    Start server and monitor certificates
    """
    # parse script arguments
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__.strip(),
        usage=argparse.SUPPRESS,
    )
    subparsers = parser.add_subparsers(dest='command', help=argparse.SUPPRESS)

    # new account parser
    new_parser = subparsers.add_parser('new-account', help='create new account')
    new_parser.add_argument('account_path', help='path to account directory with configuration and certificates')
    for group in new_parser._action_groups:
        group.title = 'arguments'

    # update account parser
    update_parser = subparsers.add_parser('update-account', help='update existing account')
    update_parser.add_argument('account_path', help='path to account directory with configuration and certificates')

    # deactivate account
    deactivate_parser = subparsers.add_parser('deactivate-account', help='deactivate existing account')
    deactivate_parser.add_argument('account_path', help='path to account directory with configuration and certificates')

    # run
    run_parser = subparsers.add_parser('run', help='run certificate validatin and monitoring')
    run_parser.add_argument('account_path', help='path to account directory with configuration and certificates')

    # renew
    renew_parser = subparsers.add_parser('renew', help='renew domain certificates')
    renew_parser.add_argument('account_path', help='path to account directory with configuration and certificates')
    renew_parser.add_argument('--domain', metavar='domain', nargs='+', required=True, help='domain to renew')
    renew_parser.add_argument('--force', action='store_true', help='force domain renewal')

    # revoke
    revoke_parser = subparsers.add_parser('revoke', help='revoke domain certificates')
    revoke_parser.add_argument('account_path',help='path to account directory with configuration and certificates')
    revoke_parser.add_argument('--domain', metavar='domain', nargs='+', required=True, help='domain to revoke')

    # renew-all
    renew_all_parser = subparsers.add_parser('renew-all', help='renew certificates for all configured domains')
    renew_all_parser.add_argument('account_path', help='path to account directory with configuration and certificates')
    renew_all_parser.add_argument('--force', action='store_true', help='force domain renewal')

    # revoke-all
    revoke_all_parser = subparsers.add_parser('revoke-all', help='revoke certificates for all configured domains')
    revoke_all_parser.add_argument('account_path', help='path to account directory with configuration and certificates')

    # version
    subparsers.add_parser('version', help='show acme-tls version')

    # testing
    parser.add_argument('--testing', action='store_true', default=False, help=argparse.SUPPRESS)

    # parse
    args = parser.parse_args()
    try:
        if args.command is None:
            print(parser.description)
            return 2
        elif args.command == 'new-account':
            check_openssl()
            check_account_path(args.account_path)
            config = read_config(os.path.join(args.account_path, 'config'))
            return run_new_account(args.account_path, config, args.testing)
        elif args.command == 'update-account':
            check_openssl()
            check_account_path(args.account_path)
            config = read_config(os.path.join(args.account_path, 'config'))
            return run_update_account(args.account_path, config, args.testing)
        elif args.command == 'deactivate-account':
            check_openssl()
            check_account_path(args.account_path)
            config = read_config(os.path.join(args.account_path, 'config'))
            return run_deactivate_account(args.account_path, config, args.testing)
        elif args.command == 'run':
            check_openssl()
            check_account_path(args.account_path)
            config = read_config(os.path.join(args.account_path, 'config'))
            return run_auto(args.account_path, config, args.testing)
        elif args.command == 'renew':
            check_openssl()
            check_account_path(args.account_path)
            config = read_config(os.path.join(args.account_path, 'config'))
            return run_renew(args.account_path, config, args.domain, args.force, args.testing)
        elif args.command == 'revoke':
            check_openssl()
            check_account_path(args.account_path)
            config = read_config(os.path.join(args.account_path, 'config'))
            return run_revoke(args.account_path, config, args.domain, args.testing)
        elif args.command == 'renew-all':
            check_openssl()
            check_account_path(args.account_path)
            config = read_config(os.path.join(args.account_path, 'config'))
            return run_renew_all(args.account_path, config, args.force, args.testing)
        elif args.command == 'revoke-all':
            check_openssl()
            check_account_path(args.account_path)
            config = read_config(os.path.join(args.account_path, 'config'))
            return run_revoke_all(args.account_path, config, args.testing)
        elif args.command == 'version':
            print(f'acme-tls {cfg.version}')
            return 0
    except RuntimeError as exc:
        print(exc)
        return 1
    except Exception:
        traceback.print_exc()
        return 3
    except KeyboardInterrupt:
        print('watchdog: exiting on user request')
        return 0


# entrypoint
if __name__ == '__main__':
    sys.exit(main())
