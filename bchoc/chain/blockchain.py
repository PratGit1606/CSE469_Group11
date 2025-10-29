from bchoc.utils.block import Block, ZERO32
from typing import List, Iterator, Optional
import bchoc.persistence.persistence as persistence
import bchoc.crypto.cryptography as cryptography


# --- PUBLIC API ----- #

# add a fully packed block to the chain file
# (assumes that Core already set prev_hash)
def add_block(block_bytes: bytes) -> bool:
    try:
        path = persistence.resolve_path()
        with persistence.open_chain(path, mode="ab") as f:
            persistence.append_block(f, block_bytes)
        return True
    except Exception:
        return False

# reads the whole block file and checks that each hash == prev_hash
def verify_chain()-> dict:
    result = {
        "count": 0,
        "state": "CLEAN",
        "error_kind": None,
        "bad_block_index": None,
        "expected_prev_hash": None,
        "found_prev_hash": None
    }

    try:
        blocks = list(_iterate_raw_blocks())
        result["count"] = len(blocks)

        # no blocks found
        if result["count"] == 0:
            result["state"] = "ERROR"
            result["error_kind"] = "NO_BLOCKS"
            return result
        

        first_block = Block.unpack_block(blocks[0])
        if not first_block.is_genesis():
            result["state"] = "ERROR"
            result["error_kind"] = "INVALID_GENESIS"
            result["bad_block_index"] = 0
            result["expected_prev_hash"] = ZERO32.hex()
            result["found_prev_hash"] = first_block.prev_hash.hex()
            return result
        
        # verify the rest of the blocks
        parent_hashes = {} # keep track of parents 

        for i in range(1, len(blocks)):
            current_block = Block.unpack_block(blocks[i])
            prev_block_bytes = blocks[i - 1]

            # compute hash of prev block
            expected_hash = cryptography.compute_block_hash(prev_block_bytes)

            # check if current block prev hash matches
            if current_block.prev_hash != expected_hash:
                result["state"] = "ERROR"
                result["error_kind"] = "HASH_MISMATCH"
                result["bad_block_index"] = i
                result["expected_prev_hash"] = expected_hash.hex()
                result["found_prev_hash"] = current_block.prev_hash.hex()
                return result
            
            # check for duplicate parent blocks
            parent_hash = current_block.prev_hash
            if parent_hash in parent_hashes:
                result["state"] = "ERROR"
                result["error_kind"] = "DUPLICATE_PARENT"
                result["bad_block_index"] = i
                result["expected_prev_hash"] = None
                result["found_prev_hash"] = parent_hash.hex()
                return result
            parent_hashes[parent_hash] = i

        # check for item state violations
        item_states = {} # item_id -> (last_state, block_index)

        for i, block_bytes in enumerate(blocks):
            block = Block.unpack_block(block_bytes)
            item_id = block.item_id
            state = block.state

            # skip the genesis block
            if block.is_genesis():
                continue

            # check for duplicate item 
            if state == 'CHECKEDIN' and item_id in item_states:
                last_state, _ = item_states[item_id]
                # if the last state wasn't CHECKOUT, this is a duplicate
                if last_state != 'CHECKEDOUT':
                    result["state"] = "ERROR"
                    result["error_kind"] = "DUPLICATE_ITEM"
                    result["bad_block_index"] = i
                    return result
                
            # check for actions after removal
            if item_id in item_states:
                last_state, _ = item_states[item_id]
                if last_state in ['DISPOSED', 'DESTROYED', 'RELEASED']:
                    if state in ['CHECKEDIN', 'CHECKEDOUT']:
                        result["state"] = "ERROR"
                        result["error_kind"] = "ACTION_AFTER_REMOVAL"
                        result["bad_block_index"] = i
                        return result
                    
            # check for double checkout
            if item_id in item_states:
                last_state, _ = item_states[item_id]
                if state == 'CHECKEDOUT' and last_state == 'CHECKEDOUT':
                    result["state"] = "ERROR"
                    result["error_kind"] = "DOUBLE_CHECKOUT"
                    result["bad_block_index"] = i
                    return result

            # check for double remove
            if state in ['DISPOSED', 'DESTROYED', 'RELEASED']:
                if item_id in item_states:
                    last_state, _ = item_states[item_id]
                    if last_state in ['DISPOSED', 'DESTROYED', 'RELEASED']:
                        result["state"] = "ERROR"
                        result["error_kind"] = "DOUBLE_REMOVE"
                        result["bad_block_index"] = i
                        return result
                    
            item_states[item_id] = (state, i)

    except Exception as e:
        result["state"] = "ERROR"
        result["error_kind"] = "EXCEPTION"
        result["exception"] = str(e)

    return result

            

def blocks_by_item(item_id: bytes) -> List[bytes]:
    # returns a list of packed blocks where item_id matches given item_id
    # (oldest -> newest)
    return _filter_blocks(case_id = None, item_id = item_id, limit = None, reverse = False)

def blocks_by_case(case_id: bytes) -> List[bytes]:
    # returns a list of packed blocks where case_id matches given case_id
    # (oldest -> newest)
    return _filter_blocks(case_id = case_id, item_id = None, limit = None, reverse = False)

def blocks_by_history(case_id: bytes, item_id: bytes, 
                      num_entries: int, reverse: bool) -> List[bytes]:
    # same... case_id/item_id may be NONE
    return _filter_blocks(case_id = case_id, item_id = item_id, limit = num_entries, reverse = reverse)


# --- INTERNAL HELPERS ----- #

def _iterate_raw_blocks() -> Iterator[bytes]:
    # stream the file with Persitence and give back raw block bytes 
    # in order
    path = persistence.resolve_path()
    if not persistence.file_exists(path):
        return
    
    with persistence.open_chain(path, mode="rb") as f:
        for offset, raw_bytes in persistence.read_blocks(f):
            yield raw_bytes

def _filter_blocks(case_id: bytes, item_id: bytes,
                   limit: int, reverse: bool) -> List[bytes]:
    # decode each raw block with Block.unpack_block and apply filters
    matching_blocks = []

    for raw_block in _iterate_raw_blocks():
        block = Block.unpack_block(raw_block)

        if case_id is not None and block.case_id != case_id:
            continue

        if item_id is not None and block.item_id != item_id:
            continue

        matching_blocks.append(raw_block)

    if reverse:
            matching_blocks.reverse()
        
    if limit is not None and limit > 0:
            matching_blocks = matching_blocks[:limit]

    return matching_blocks


