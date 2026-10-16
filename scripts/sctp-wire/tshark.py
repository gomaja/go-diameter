"""Run tshark against a capture using the tools image recorded by its runner."""
import pathlib
import subprocess
import uuid


def tshark(out, capture, *arguments):
    out = pathlib.Path(out).resolve()
    run = (out / 'run-id').read_text().strip()
    image_file = out / 'image-id.txt'
    image = image_file.read_text().strip() if image_file.exists() else 'sctp-wire-tools:go1.27.2'
    command = ['docker', 'run', '--rm', '--name', f'{run}-tshark-{uuid.uuid4().hex}',
               '--label', f'harness={run}', '--mount',
               f'type=bind,src={out},dst=/evidence,readonly', image,
               'tshark', '-r', f'/evidence/{capture}', *arguments]
    return subprocess.run(command, text=True, capture_output=True, check=True)
