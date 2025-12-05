# Justin Guerrero - 1224417753
# Middle layer between CLI and blockchain operations

from uuid import UUID
from typing import List, Optional
import cryptography as cryptography

from blockchain import add_block
from block import Block
from errors import BchocError, ExitCode
from timefmt import utc_epoch
from validators import (
    validate_password, validate_item_id, validate_uuid,
    validate_password_role, validate_removal_reason
)
from security import (
    item_exists, checkout_allowed, checkin_allowed, remove_allowed,
    get_item_state, get_item_case_id, get_item_creator,
    get_last_block_bytes, sort_cases, sort_case_items,
    get_block_history, get_case_summary
)

VALID_STATES = ["INITIAL", "CHECKEDIN", "CHECKEDOUT",
                "DISPOSED", "DESTROYED", "RELEASED"]

def pad32(b: bytes) -> bytes:
    return b.ljust(32, b'\x00')

def pad12(s: str) -> bytes:
    return s.encode().ljust(12, b'\x00')

def init_handler() -> int:
    try:
        last_block = get_last_block_bytes()

        if last_block is not None:
            print("Blockchain already exists with an INITIAL block.")
            return ExitCode.OK

        blk = Block()
        blk.prev_hash = b'\x00' * 32
        blk.timestamp = 0.0
        blk.case_id = b"0" * 32                     
        blk.item_id = b"0" * 32   
        blk.state = "INITIAL"
        blk.creator = ""
        blk.owner = ""
        blk.data = b"Initial block\x00"

        add_block(blk.pack_block())
        print("Blockchain file created with INITIAL block.")
        return ExitCode.OK

    except Exception:
        return ExitCode.E_GENERAL



def add_handler(case_id: str, item_ids: List[int], creator: str, password: str) -> tuple:
    try:
        if not validate_password(password, "CREATOR"):
            raise BchocError(ExitCode.E_AUTH, "Invalid password.")

        if not validate_uuid(case_id):
            raise BchocError(ExitCode.E_ARGS, "Invalid Case ID.")

        case_uuid = UUID(case_id)
        encrypted_case_id = pad32(cryptography.encrypt_id(case_uuid.bytes))
        
        timestamps = []
        
        last_block_bytes = get_last_block_bytes()
        if last_block_bytes is None:
            blk = Block()
            blk.prev_hash = b'\x00' * 32
            blk.timestamp = 0.0
            blk.case_id = b"0" * 32                     
            blk.item_id = b"0" * 32   
            blk.state = "INITIAL"
            blk.creator = ""
            blk.owner = ""
            blk.data = b"Initial block\x00"

            add_block(blk.pack_block())
            last_block_bytes = blk.pack_block()

        for item_id in item_ids:
            if item_exists(item_id):
                raise BchocError(ExitCode.E_STATE, "This item already exists.")

            if not validate_item_id(item_id):
                raise BchocError(ExitCode.E_ARGS, "Invalid item ID.")

            encrypted_item_id = pad32(cryptography.encrypt_id(item_id.to_bytes(4, 'big')))

            timestamp = utc_epoch()
            
            blk = Block()
            blk.prev_hash = cryptography.compute_block_hash(last_block_bytes)
            blk.timestamp = timestamp
            blk.case_id = encrypted_case_id
            blk.item_id = encrypted_item_id
            blk.state = "CHECKEDIN"
            blk.creator = creator[:12] if len(creator) <= 12 else creator[:12]
            blk.owner = ""
            blk.data = b""

            block_bytes = blk.pack_block()
            add_block(block_bytes)
            timestamps.append(timestamp)
            
            # CRITICAL: Update last_block_bytes for next iteration
            last_block_bytes = block_bytes

        return (ExitCode.OK, case_id, timestamps)

    except BchocError as e:
        raise e
    except Exception as e:
        raise BchocError(ExitCode.E_GENERAL, f"Error in add_handler: {str(e)}")


def checkout_handler(item_id: int, password: str) -> tuple:
    try:
        if not validate_password(password, "OWNER"):
            raise BchocError(ExitCode.E_AUTH, "Invalid password.")

        if not item_exists(item_id):
            raise BchocError(ExitCode.E_STATE, "Evidence item not found.")

        if not validate_item_id(item_id):
            raise BchocError(ExitCode.E_ARGS, "Invalid item ID.")

        if not checkout_allowed(item_id):
            raise BchocError(ExitCode.E_STATE, "Item cannot be checked out in its current state.")

        encrypted_case_id_bytes = get_item_case_id(item_id)
    
        decrypted_case_id = cryptography.decrypt_id(encrypted_case_id_bytes[:16])
        case_id = str(UUID(bytes=decrypted_case_id))
        
        encrypted_case_id = pad32(encrypted_case_id_bytes)
        encrypted_item_id = pad32(cryptography.encrypt_id(item_id.to_bytes(4, 'big')))

        last_block_bytes = get_last_block_bytes()
        if last_block_bytes is None:
            raise BchocError(ExitCode.E_IO, "Blockchain not initialized.")

        owner_str = validate_password_role(password, "OWNER")
        creator_bytes = get_item_creator(item_id)
        
        timestamp = utc_epoch()

        blk = Block()
        blk.prev_hash = cryptography.compute_block_hash(last_block_bytes)
        blk.timestamp = timestamp
        blk.case_id = encrypted_case_id
        blk.item_id = encrypted_item_id
        blk.state = "CHECKEDOUT"
        blk.creator = creator_bytes if isinstance(creator_bytes, str) else creator_bytes.decode()
        blk.owner = owner_str
        blk.data = b""

        add_block(blk.pack_block())
        
        return (ExitCode.OK, case_id, timestamp)

    except BchocError as e:
        raise e
    except Exception:
        return (ExitCode.E_GENERAL, None, None)


def checkin_handler(item_id: int, password: str) -> tuple:
    try:
        if not validate_password(password, "OWNER"):
            raise BchocError(ExitCode.E_AUTH, "Invalid password.")

        if not item_exists(item_id):
            raise BchocError(ExitCode.E_STATE, "Evidence item not found.")

        if not validate_item_id(item_id):
            raise BchocError(ExitCode.E_ARGS, "Invalid item ID.")

        if not checkin_allowed(item_id):
            raise BchocError(ExitCode.E_STATE, "Item cannot be checked in in its current state.")

        encrypted_case_id_bytes = get_item_case_id(item_id)
    
        decrypted_case_id = cryptography.decrypt_id(encrypted_case_id_bytes[:16])
        case_id = str(UUID(bytes=decrypted_case_id))
        
        encrypted_case_id = pad32(encrypted_case_id_bytes)
        encrypted_item_id = pad32(cryptography.encrypt_id(item_id.to_bytes(4, 'big')))

        last_block_bytes = get_last_block_bytes()
        if last_block_bytes is None:
            raise BchocError(ExitCode.E_IO, "Blockchain not initialized.")

        owner_str = validate_password_role(password, "OWNER")
        creator_bytes = get_item_creator(item_id)
        
        timestamp = utc_epoch()

        blk = Block()
        blk.prev_hash = cryptography.compute_block_hash(last_block_bytes)
        blk.timestamp = timestamp
        blk.case_id = encrypted_case_id
        blk.item_id = encrypted_item_id
        blk.state = "CHECKEDIN"
        blk.creator = creator_bytes if isinstance(creator_bytes, str) else creator_bytes.decode()
        blk.owner = owner_str
        blk.data = b""

        add_block(blk.pack_block())
        
        return (ExitCode.OK, case_id, timestamp)

    except BchocError as e:
        raise e
    except Exception:
        return (ExitCode.E_GENERAL, None, None)


def remove_handler(item_id: int, reason: str, owner: Optional[str], password: str) -> tuple:
    if not validate_password(password, "CREATOR"):
        raise BchocError(ExitCode.E_AUTH, "Invalid password.")

    if not item_exists(item_id):
        raise BchocError(ExitCode.E_STATE, "Evidence item not found.")

    if not validate_item_id(item_id):
        raise BchocError(ExitCode.E_ARGS, "Invalid item ID.")

    if not validate_removal_reason(reason):
        raise BchocError(ExitCode.E_ARGS, "Invalid removal reason.")

    if not remove_allowed(item_id):
        raise BchocError(ExitCode.E_STATE, "Cannot remove item in its current state.")

    encrypted_case_id_bytes = get_item_case_id(item_id)
    
    decrypted_case_id = cryptography.decrypt_id(encrypted_case_id_bytes[:16])
    case_id = str(UUID(bytes=decrypted_case_id))
    
    encrypted_case_id = pad32(encrypted_case_id_bytes)
    encrypted_item_id = pad32(cryptography.encrypt_id(item_id.to_bytes(4, 'big')))

    last_block_bytes = get_last_block_bytes()
    if last_block_bytes is None:
        raise BchocError(ExitCode.E_IO, "Blockchain not initialized.")

    creator_bytes = get_item_creator(item_id)
    owner_bytes = owner.encode() if (reason == "RELEASED" and owner) else b""
    
    timestamp = utc_epoch()

    blk = Block()
    blk.prev_hash = cryptography.compute_block_hash(last_block_bytes)
    blk.timestamp = timestamp
    blk.case_id = encrypted_case_id
    blk.item_id = encrypted_item_id
    blk.state = reason
    blk.creator = creator_bytes if isinstance(creator_bytes, str) else creator_bytes.decode()
    blk.owner = owner_bytes.decode() if isinstance(owner_bytes, bytes) else owner_bytes
    blk.data = b""

    add_block(blk.pack_block())
    
    return (ExitCode.OK, case_id, timestamp, reason)  


def show_cases_handler(password: str) -> List[str]:
    if not validate_password(password, "OWNER"):
        raise BchocError(ExitCode.E_AUTH, "Invalid password/Higher clearance needed.")
    return sort_cases(password)



def show_items_handler(case_id: str, password: str) -> List[int]:
    if not validate_uuid(case_id):
        raise BchocError(ExitCode.E_ARGS, "Invalid case ID.")

    if not validate_password(password, "OWNER"):
        raise BchocError(ExitCode.E_AUTH, "Invalid password/Higher clearance needed.")

    return sort_case_items(case_id)


def show_history_handler(case_id: Optional[str], item_id: Optional[int],
                         num_entries: Optional[int], reverse: bool,
                         password: str) -> List[dict]:

    if not validate_password(password, "OWNER"):
        raise BchocError(ExitCode.E_AUTH, "Invalid password.")

    if case_id is not None and not validate_uuid(case_id):
        raise BchocError(ExitCode.E_ARGS, "Invalid case ID.")

    if item_id is not None and not validate_item_id(item_id):
        raise BchocError(ExitCode.E_ARGS, "Invalid item ID.")

    if num_entries is not None and (not isinstance(num_entries, int) or num_entries <= 0):
        raise BchocError(ExitCode.E_ARGS, "Invalid number of entries.")

    return get_block_history(case_id, item_id, num_entries, reverse)


def summary_handler(case_id: str) -> dict:
    if not validate_uuid(case_id):
        raise BchocError(ExitCode.E_ARGS, "Invalid case ID.")
    return get_case_summary(case_id)


def verify_handler():
    from blockchain import verify_chain
    return verify_chain()
