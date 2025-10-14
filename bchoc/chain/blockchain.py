from utils import Block
from typing import List
from typing import Iterator



# --- PUBLIC API ----- #

# add a fully packed block to the chain file
# (assumes that Core already set prev_hash)
def add_block(block_bytes: bytes) -> bool:
    pass

# reads the whole block file and checks that each hash == prev_hash
def verify_chain()-> dict:
    # first block: 
    # prev_hash == ZERO32

    # every other block: 
    # block.prev_hash == sha256(prev_block)

    # returns a summary dict for Util to parse
#    {
#     "count": 5,                        # total number of blocks scanned
#     "state": "CLEAN",                  # chain integrity is good
#     "error_kind": None,                # no errors detected
#     "bad_block_index": None,           # no block failed validation
#     "expected_prev_hash": None,        # not applicable
#     "found_prev_hash": None            # not applicable
# }
    pass

def blocks_by_item(item_id: bytes) -> List[bytes]:
    # returns a list of packed blocks where item_id matches given item_id
    # (oldest -> newest)
    pass

def blocks_by_case(case_id: bytes) -> List[bytes]:
    # returns a list of packed blocks where case_id matches given case_id
    # (oldest -> newest)
    pass

def blocks_by_history(case_id: bytes, item_id: bytes, 
                      num_entries: int, reverse: bool) -> List[bytes]:
    # same... case_id/item_id may be NONE
    pass


# --- INTERNAL HELPERS ----- #

def _iterate_raw_blocks() -> Iterator[bytes]:
    # stream the file with Persitence and give back raw block bytes 
    # in order
    pass

def _filter_blocks(case_id: bytes, item_id: bytes,
                   limit: int, reverse: bool) -> List[bytes]:
    # decode each raw block with Block.unpack_block and apply filters
    pass


