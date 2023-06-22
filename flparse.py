from typing import Generator, Dict, List, Union
import sys
import json


def get_metadata(flp: bytes) -> Generator[tuple[str, str], None, None]:
    stop_version = flp.find(b'\x00', 20, None)
    start_fields = flp.find(b'\xc2', stop_version, None)
    stop_fields = flp.find(b'\x3F\xE7', start_fields, None)
    yield 'version', flp[20:stop_version].decode('utf-8')
    yield from (
        (key, field[2:].decode('utf-8')) for field in map(
            lambda f: f.translate(None, delete=b'\x00'),
            flp[start_fields:stop_fields].split(b'\x00\x00')[:-2]
        ) if len(field) > 2 if (key := {
            194: 'title',
            195: 'comments',
            197: 'web link',
            202: 'data folder',
            206: 'genre',
            207: 'author'
        }.get(field[0]))
    )


def get_samples(flp: bytes) -> Generator[str, None, None]:
    samples = -1
    while (samples := flp.find(b'\x00\x00\x00\x14\x00\xC4', samples + 1, None)) != -1:
        samples += 7
        yield flp[
            samples + bool(flp[samples] == 1): samples + flp[samples - 1]
        ].translate(None, delete=b'\x00').decode('utf-8')


def get_plugins(flp: bytes) -> Generator[str, None, None]:
    def previous_null_byte(i_: int, byt: bytes) -> int:
        i_2 = int(i_)
        while byt[i_2] != 0:
            i_2 -= 1
        return i_2

    for ext in (b'.dll', b'.vst'):
        stop = -1
        while (stop := flp.find(ext, stop + 1, None)) != -1:
            yield flp[
                previous_null_byte(stop, flp) + 1: stop + len(ext) + bool(
                    ext == b'.vst'
                    and chr(flp[stop + len(ext)]) in ('2', '3')
                )
            ].decode('utf-8')


def main(fp: str) -> Dict[str, Union[Dict, List]]:
    with open(fp, 'rb') as f:
        if f.read(4) != b'FLhd':
            raise ValueError(f'bad magic number in file')
        
        flp = f.read()
    return {'metadata': dict(get_metadata(flp)), 'samples': list(get_samples(flp)), 'plugins': list(get_plugins(flp))}


if (
    __name__ == "__main__"
    and len(sys.argv) > 1
):
    json.dump(obj=main(sys.argv[1]), fp=sys.stdout, indent=4)


