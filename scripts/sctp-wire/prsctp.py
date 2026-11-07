"""Check default-off PR-SCTP offers without confusing reported parameters."""
import json
import pathlib


def _pairs(items):
    # tshark JSON can repeat keys for same-type chunks or parameters.
    result = {}
    for key, value in items:
        if key in result:
            if not isinstance(result[key], list):
                result[key] = [result[key]]
            result[key].append(value)
        else:
            result[key] = value
    return result


def _objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _objects(child)


def _parameters(chunk):
    for value in chunk.values():
        values = value if isinstance(value, list) else [value]
        for parameter in values:
            if isinstance(parameter, dict) and 'sctp.parameter_type' in parameter:
                yield parameter


def assert_default_off(packets, go_ports, raw_port, prsctp_enable):
    """Check setup offers and accepted-socket restart answers separately."""
    assert prsctp_enable in (0, 1), 'prsctp_enable must be 0 or 1'
    chunks = []
    for packet in packets:
        layers = packet['_source']['layers']
        sctp = layers['sctp']
        for chunk in _objects(sctp):
            if chunk.get('sctp.chunk_type') in ('1', '2'):
                chunks.append((layers, sctp, chunk))
    chunks.sort(key=lambda item: int(item[0]['frame']['frame.number']))
    assert chunks, 'no SCTP INIT or INIT ACK captured'
    first_tags = {}
    answers = {}
    for layers, sctp, chunk in chunks:
        if not (chunk['sctp.chunk_type'] == '1' and
                sctp['sctp.srcport'] == raw_port and sctp['sctp.dstport'] == go_ports[0]):
            continue
        direct = [parameter['sctp.parameter_type'] for parameter in _parameters(chunk)]
        assert '0xc000' in direct, 'raw client did not offer Forward-TSN-Supported'
        pair = (layers['ip']['ip.src'], sctp['sctp.srcport'],
                layers['ip']['ip.dst'], sctp['sctp.dstport'])
        tag = chunk['sctp.init_initiate_tag']
        restart = tag != first_tags.setdefault(pair, tag)
        reverse = (pair[2], pair[3], pair[0], pair[1])
        matching = [(ack_layers, ack) for ack_layers, ack_sctp, ack in chunks
                    if ack['sctp.chunk_type'] == '2' and
                    (ack_layers['ip']['ip.src'], ack_sctp['sctp.srcport'],
                     ack_layers['ip']['ip.dst'], ack_sctp['sctp.dstport']) == reverse and
                    ack_sctp['sctp.verification_tag'] == tag and
                    int(ack_layers['frame']['frame.number']) > int(layers['frame']['frame.number'])]
        assert matching, 'raw-client INIT has no matching INIT ACK'
        for ack_layers, ack in matching:
            answers[id(ack)] = restart
    checked = 0
    handshake_answers = restart_answers = 0
    for layers, sctp, chunk in chunks:
        src, dst = sctp['sctp.srcport'], sctp['sctp.dstport']
        raw_client = src == raw_port and dst == go_ports[0]
        if not (src in go_ports or (dst in go_ports and not raw_client)):
            continue
        direct = [parameter['sctp.parameter_type'] for parameter in _parameters(chunk)]
        frame = layers['frame']['frame.number']
        restart = answers.get(id(chunk), False)
        reported = [nested['sctp.parameter_type']
                    for parameter in _parameters(chunk)
                    if parameter['sctp.parameter_type'] == '0x0008'
                    for nested in _parameters(parameter)]
        if restart and prsctp_enable:
            # RFC 9260 §5.2.2: this INIT restarts an accepted association.
            assert '0xc000' not in reported, (
                "Linux now answers restarts from the listener's setting; "
                'Server.SCTPPartialReliability, the README and this check need updating '
                f'(frame {frame})')
            assert '0xc000' in direct, (f'go-diameter restart frame {frame} '
                'does not offer Forward-TSN-Supported with prsctp_enable=1')
        else:
            # RFC 3758 §3.1: the direct parameter offers Forward TSN support.
            kind = 'restart ' if restart else ''
            assert '0xc000' not in direct, (f'go-diameter {kind}frame {frame} '
                'offers Forward-TSN-Supported')
        if id(chunk) in answers:
            if not (restart and prsctp_enable):
                # RFC 3758 §3.3.2: report the unwanted offer as unrecognized.
                assert '0xc000' in reported, (f'go-diameter frame {frame} does not report '
                    'Forward-TSN-Supported in Unrecognized Parameter')
            if restart:
                restart_answers += 1
            else:
                handshake_answers += 1
        checked += 1
    assert checked, 'no go-diameter INIT or INIT ACK captured'
    assert handshake_answers, 'no raw-client handshake answer captured'
    assert restart_answers, 'no raw-client restart answer captured'
    print(f'PASS: {checked} go-diameter INIT/INIT ACK chunks checked; '
          f'{handshake_answers} raw-client handshake answers decline PR-SCTP; '
          f'{restart_answers} restart answers follow prsctp_enable={prsctp_enable}.')


def read_prsctp_enable(out):
    path = out / 'prsctp_enable'
    assert path.is_file(), f'missing server sysctl file: {path}'
    value = path.read_text().strip()
    assert value in ('0', '1'), f'{path} must contain 0 or 1'
    return int(value)


def analyze_default_off(out, capture, tshark, go_ports, raw_port, prsctp_enable):
    result = tshark(out, capture, '-Y', 'sctp.chunk_type == 1 || sctp.chunk_type == 2', '-T', 'json')
    stem = pathlib.Path(capture).stem
    (out / f'{stem}-prsctp.json').write_text(result.stdout)
    (out / f'{stem}-prsctp-errors.txt').write_text(result.stderr)
    assert_default_off(json.loads(result.stdout, object_pairs_hook=_pairs), go_ports, raw_port, prsctp_enable)
