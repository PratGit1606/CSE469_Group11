#Done by Raj Sarode
import os
from typing import BinaryIO, Iterator, Tuple

from errors import BchocError, ExitCode
from block import HEADER_SIZE, Block


def resolve_path() -> str:
    # Return path to the blockchain data file (env BCHOC_FILE_PATH if set, else default).
    env_path = os.getenv("BCHOC_FILE_PATH")
    if env_path:
        return env_path
    return os.path.join(os.getcwd(), "bchoc.dat")


def file_exists(path: str | None = None) -> bool:
    # Check whether the blockchain file exists on the disk.
    if path is None:
        path = resolve_path()
    return os.path.exists(path)


def open_chain(path: str, mode: str = "rb") -> BinaryIO:
    # Open the blockchain file in the given binary mode ('w+b', 'r+b', 'a+b').
    try:
        return open(path, mode)
    except OSError as e:
        raise BchocError(ExitCode.E_IO, f"Failed to open blockchain file '{path}': {e}") from e


def append_block(f: BinaryIO, block_bytes: bytes) -> int:
    # Append one packed block at EOF and return its starting file offset.
    try:
        f.seek(0, os.SEEK_END)
        offset = f.tell()
        f.write(block_bytes)
        f.flush()
        os.fsync(f.fileno())
        return offset
    except OSError as e:
        raise BchocError(ExitCode.E_IO, f"Failed to append block: {e}") from e


def read_blocks(f: BinaryIO) -> Iterator[Tuple[int, bytes]]:
    # Iterate over all blocks in the file and yield (offset, raw_block_bytes).
    try:
        while True:
            offset = f.tell()
            header = f.read(HEADER_SIZE)
            if not header:
                break
            if len(header) != HEADER_SIZE:
                raise BchocError(
                    ExitCode.E_IO,
                    f"Truncated header at offset {offset} "
                    f"(expected {HEADER_SIZE}, got {len(header)})",
                )

            # unpack header to learn data length
            _, _, _, _, _, _, _, data_len = Block.unpack_header(header)

            data = f.read(data_len)
            if len(data) != data_len:
                raise BchocError(
                    ExitCode.E_IO,
                    f"Truncated data at offset {offset} "
                    f"(expected {data_len}, got {len(data)})",
                )

            yield offset, header + data
    except OSError as e:
        raise BchocError(ExitCode.E_IO, f"Error reading blockchain file: {e}") from e
