# Justin Guerrero - 1224417753
# Security/state logic for blockchain operations

from typing import Optional, List
from block import Block
import blockchain as chain
from cryptography import encrypt_id, decrypt_id
import uuid


def pad32(b: bytes) -> bytes:
    return b.ljust(32, b'\x00')

def get_item_state(item_id: int) -> Optional[str]:
    try:
        item_id_bytes = item_id.to_bytes(4, 'big')
        encrypted_item_id = pad32(encrypt_id(item_id_bytes))

        blocks = chain.blocks_by_item(encrypted_item_id)
        if blocks:
            block = Block.unpack_block(blocks[-1])
            return block.state

        return None

    except Exception:
        return None



def get_item_case_id(item_id: int) -> Optional[bytes]:
    try:
        item_id_bytes = item_id.to_bytes(4, 'big')
        encrypted_item_id = pad32(encrypt_id(item_id_bytes))

        blocks = chain.blocks_by_item(encrypted_item_id)
        if not blocks:
            return None

        for block_bytes in blocks:
            block = Block.unpack_block(block_bytes)
            if block.is_genesis():
                continue
            return block.case_id

        return None

    except Exception:
        return None



def item_exists(item_id: int) -> bool:
    return get_item_state(item_id) is not None



def checkout_allowed(item_id: int) -> bool:
    state = get_item_state(item_id)
    if state is None:
        return False

    if state in ["DISPOSED", "DESTROYED", "RELEASED"]:
        return False

    return state == "CHECKEDIN"


def checkin_allowed(item_id: int) -> bool:
    state = get_item_state(item_id)
    if state is None:
        return False

    if state in ["DISPOSED", "DESTROYED", "RELEASED"]:
        return False

    return state == "CHECKEDOUT"


def remove_allowed(item_id: int) -> bool:
    return get_item_state(item_id) == "CHECKEDIN"


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



def get_item_creator(item_id: int) -> str:
    try:
        item_id_bytes = item_id.to_bytes(4, 'big')
        encrypted_item_id = pad32(encrypt_id(item_id_bytes))
        blocks = chain.blocks_by_item(encrypted_item_id)
        if blocks:
            first_block = Block.unpack_block(blocks[0])
            return first_block.creator
        return ""

    except Exception:
        return ""



def sort_cases(password: str) -> List[str]:
    case_ids = set()

    for raw_block in chain._iterate_raw_blocks():
        block = Block.unpack_block(raw_block)
        if block.is_genesis():
            continue

        decrypted_case_id = decrypt_id(block.case_id[:16])
        cid = uuid.UUID(bytes=decrypted_case_id)
        case_ids.add(str(cid))

    return sorted(list(case_ids))



def sort_case_items(case_id: str) -> List[int]:
    case_id_bytes = uuid.UUID(case_id).bytes
    encrypted_case_id = pad32(encrypt_id(case_id_bytes))
    blocks = chain.blocks_by_case(encrypted_case_id)

    item_ids = set()

    for block_bytes in blocks:
        block = Block.unpack_block(block_bytes)
        if block.is_genesis():
            continue

        decrypted_id = decrypt_id(block.item_id[:16])
        item_int = int.from_bytes(decrypted_id[:4], 'big')
        item_ids.add(item_int)

    return sorted(list(item_ids))


def get_block_history(case_id: Optional[str], item_id: Optional[int],
                      num_entries: Optional[int], reverse: bool) -> List[dict]:

    case_id_bytes = None
    if case_id:
        case_uuid_bytes = uuid.UUID(case_id).bytes
        case_id_bytes = pad32(encrypt_id(case_uuid_bytes))

    item_id_filter = None
    if item_id is not None:
        encrypted_item = pad32(encrypt_id(item_id.to_bytes(4, 'big')))
        item_id_filter = encrypted_item

    blocks = chain.blocks_by_history(
        case_id=case_id_bytes,
        item_id=item_id_filter,
        num_entries=num_entries if num_entries else None,
        reverse=reverse
    )

    history = []
    for block_bytes in blocks:
        block = Block.unpack_block(block_bytes)
        if block.is_genesis():
            continue

        decrypted_case_id = decrypt_id(block.case_id[:16])
        case_uuid = uuid.UUID(bytes=decrypted_case_id)
        
        # Decrypt item_id
        decrypted_item_id = decrypt_id(block.item_id[:16])
        item_int = int.from_bytes(decrypted_item_id[:4], 'big')

        entry = {
            'case_id': str(case_uuid),
            'item_id': item_int,
            'state': block.state,
            'creator': block.creator,
            'timestamp': block.timestamp,
        }
        history.append(entry)

    return history


def get_case_summary(case_id: str) -> dict:
    case_uuid_bytes = uuid.UUID(case_id).bytes
    encrypted_case_id = pad32(encrypt_id(case_uuid_bytes))
    blocks = chain.blocks_by_case(encrypted_case_id)

    item_states = {}

    for block_bytes in blocks:
        block = Block.unpack_block(block_bytes)
        if block.is_genesis():
            continue

        decrypted_id = decrypt_id(block.item_id[:16])
        item_int = int.from_bytes(decrypted_id[:4], 'big')
        state = block.state

        item_states[item_int] = state

    state_count = {
        'CHECKEDIN': 0,
        'CHECKEDOUT': 0,
        'DISPOSED': 0,
        'DESTROYED': 0,
        'RELEASED': 0
    }

    for st in item_states.values():
        if st in state_count:
            state_count[st] += 1

    summary = {
        'case_id': case_id,
        'num_items': len(item_states),
        'states': state_count,
        'checked_out': sorted([i for i, s in item_states.items() if s == "CHECKEDOUT"])
    }

    return summary

def get_item_owner(item_id: int) -> str:
    try:
        item_id_bytes = item_id.to_bytes(4, 'big')
        encrypted_item_id = pad32(encrypt_id(item_id_bytes))

        blocks = chain.blocks_by_item(encrypted_item_id)
        if blocks:
            block = Block.unpack_block(blocks[-1])  
            return block.owner

        return ""

    except Exception:
        return ""