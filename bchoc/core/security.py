# Justin Guerrero - 1224417753
# The functions in this file are responsible for state checking and validation regarding blockchain 
from typing import Optional, List
from bchoc.utils.block import Block
import bchoc.chain.blockchain as chain
from bchoc.crypto.cryptography import encrypt_id, decrypt_id
from bchoc.core.validators import validate_password
import uuid

# retrieve the current state of an evidence block by taking the bytes of the item_id and encrypting them for seaching
def get_item_state(item_id: int) -> Optional[str]:
    try: 
        item_id_bytes = item_id.to_bytes(4, 'big').ljust(32, b'\x00')
        encrypted_item_id = encrypt_id(item_id_bytes) 

        blocks = chain.blocks_by_item(encrypted_item_id)
        if blocks:
            state = blocks[-1].state.decode('utf-8').rstrip('\x00')
            return state
        
        return None
    
    except Exception:
        return None

# retrieve a block's case_id via searching with the encrypted item_id bytes of input
def get_item_case_id(item_id: int) -> Optional[bytes]:
    try: 
        item_id_bytes = item_id.to_bytes(4, 'big').ljust(32, b'\x00')
        encrypted_item_id = encrypt_id(item_id_bytes) 

        blocks = chain.blocks_by_item(encrypted_item_id)
        if not blocks:
            return None
        
        for block_bytes in blocks:
            block = Block.unpack_block(block_bytes)

            if block.item_id == b'\x00' * 32: # skip genesis block when finding case_id
                continue

            return block.case_id
        
        return None
    
    except Exception:
        return None
    
# helper to check if an item exists within the blockchain
def item_exists(item_id: int) -> bool:
    return get_item_state(item_id) is not None

# helper to check if an evidence item can be checked out of the blockchain
def checkout_allowed(item_id: int) -> bool:
    state = get_item_state(item_id)

    if (state is None) or (state in ["DISPOSED", "DESTROYED", "RELEASED"]):
        return False
    
    return state == "CHECKEDIN"
    
# helper to check if an evidence item can be checked in to the blockchain
def checkin_allowed(item_id: int) -> bool:
    state = get_item_state(item_id)
    if (state is None) or (state in ["DISPOSED", "DESTROYED", "RELEASED"]):
        return False
    
    if state in ["CHECKEDIN", "CHECKEDOUT"]:
        return True
    
    return False



# helper to check if an evidence can be fully removed from the blockchain
def remove_allowed(item_id: int) -> bool:
    state = get_item_state(item_id)
    return state == "CHECKEDIN"

# helper to retrieve bytes of the most recently added block in chain
def get_last_block_bytes() -> Optional[bytes]:
    try:
        blocks = chain.blocks_by_history(
            case_id=None,
            item_id=None,
            num_entries=1,
            reverse=True
        )
        return blocks[0] if blocks else None
    
    except Exception:
        return None
    
# helper for maintaing creator data in blocks
def get_item_creator(item_id: int) -> bytes:
    try:
        item_id_bytes = item_id.to_bytes(4, 'big').ljust(32, b'\x00')
        encrypted_item_id = encrypt_id(item_id_bytes)
        blocks = chain.blocks_by_item(encrypted_item_id)
        if blocks:
            first = Block.unpack_block(blocks[0])
            return first.creator
        
        return b'\x00' * 12
    
    except Exception:
        return b'x\00' * 12

# function to find and sort all cases within blockchain
def sort_cases(password: str) -> List[str]:
    case_ids = set()
    for raw_block in chain._iterate_raw_blocks():
        block = Block.unpack_block(raw_block)

        if not block.is_genesis():
            case_id_str = str(uuid.UUID(bytes=block.case_id))
            case_ids.add(case_id_str)

    return sorted(list(case_ids))

# function to return sorted list of item_ids
def sort_case_items(case_id: str) -> List[int]:
    case_id_bytes = uuid.UUID(case_id).bytes
    blocks = chain.blocks_by_case(case_id_bytes)
    item_ids = set()
    for block_bytes in blocks:
        block = Block.unpack_block(block_bytes)

        if block.is_genesis():
            continue

        decrypted_item_id = decrypt_id(block.item_id)
        item_id_int = int.from_bytes(decrypted_item_id[:4], 'big')
        item_ids.add(item_id_int)

    return sorted(list(item_ids))

# function for getting the history using optional case_id, item_id, and num_entries inputs
def get_block_history(case_id: Optional[str], item_id: Optional[int], num_entries: Optional[int], reverse: bool) -> List[int]:
    case_id_bytes = None
    if case_id is not None:
        case_id_bytes = uuid.UUID(case_id).bytes

    item_id_bytes = None
    if item_id is not None:
        item_id_bytes = item_id.to_bytes(4, 'big').ljust(32, b'\x00')
        item_id_bytes = encrypt_id(item_id_bytes)

    blocks = chain.blocks_by_history(
        case_id=case_id_bytes,
        item_id=item_id_bytes,
        num_entries=num_entries if num_entries else None,
        reverse=reverse
    )

    history = []
    for block_bytes in blocks:
        block = Block.unpack_block(block_bytes)

        if block.is_genesis():
            continue

        decrypted_item_id = decrypt_id(block.item_id)
        item_id_int = int.from_bytes(decrypted_item_id[:4], 'big')

        entry = {
            'case_id': str(uuid.UUID(bytes=block.case_id)),
            'item_id': item_id_int,
            'state': block.state.decode('utf-8').rstrip('\x00'),
            'creator': block.creator.decode('utf-8').rstrip('\x00'),
            'timestamp': block.timestamp.decode('utf-8').rstrip('\x00')
        }

        history.append(entry)

    return history

# function to return the summary of a case
def get_case_summary(case_id: str) -> dict:
    case_id_bytes = uuid.UUID(case_id).bytes
    blocks = chain.blocks_by_case(case_id_bytes)
    item_states = {}
    for block_bytes in blocks:
        block = Block.unpack_block(block_bytes)

        if block.is_genesis():
            continue

        decrypted_item_id = decrypt_id(block.item_id)
        item_id_int = int.from_bytes(decrypted_item_id[:4], 'big')
        state = block.state.decode('utf-8').rstrip('\x00')
        item_states[item_id_int] = state

    state_count = {
        'CHECKEDIN': 0,
        'CHECKEDOUT': 0,
        'DISPOSED': 0,
        'DESTROYED': 0,
        'RELEASED': 0
    }

    checkedout = []
    for item_id, state in item_states.items():
        if state in state_count:
            state_count[state] += 1

        if state == 'CHECKEDOUT':
            checkedout.append(item_id)

    summary = {
        'case_id': case_id,
        'num_items': len(item_states),
        'states': state_count,
        'checked_out': sorted(checkedout)
    }

    return summary

    

        
