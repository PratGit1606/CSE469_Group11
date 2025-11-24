# Justin Guerrero - 1224417753
# This file is responsible for being the middle-man between the CLI and blockchain ops
import os
import bchoc.crypto.cryptography as cryptography
from uuid import UUID
from typing import List, Optional, Tuple, Any
from bchoc.chain.blockchain import (add_block, blocks_by_case, blocks_by_history, blocks_by_item, verify_chain)
from bchoc.utils.block import pack_block, Block
from bchoc.utils.timefmt import utc_epoch, format_timestamp
from bchoc.core.security import *
from bchoc.core.validators import *

VALID_STATES = ["INITIAL", "CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"]
REMOVAL_STATES = ["DISPOSED", "DESTROYED", "RELEASED"]

# class to allow custom error codes 
class BchocError(Exception):
    def __init__(self, exit_code: int, message: str):
        self.exit_code = exit_code
        self.message = message
        super().__init__(self.message)

# custom non-zero error codes, need to discuss specific error cases
class ExitCode:
    SUCCESS = 0
    ERROR = 1

# initialize blockchain
def init_handler() -> int:
    try:
        try: # check to see if the blockchain already exists
            blocks = blocks_by_history(None, None, 1, False)
            if (blocks) and (blocks[0].state.decode('utf-8').rstrip('\x00') == "INITIAL"):
                print("Blockchain already exists with an INITIAL block.")
            else:
                raise BchocError(ExitCode.ERROR, "Existing blockchain found with missing INITIAL block.")
            
        except FileNotFoundError: # blockchain does not exist -> create INITIAL block
            genesis_bytes = pack_block(
                prev_hash = b'\x00' * 32,
                timestamp = 0,
                case_id = b'\x00' * 32,
                item_id = b'\x00' * 32,
                state = b'INITIAL\x00\x00\x00\x00\x00',
                creator = b'\x00' * 12,
                owner = b'\x00' * 12,
                data = b"Intiial block\x00"
            )
            add_block(genesis_bytes)  

        return ExitCode.SUCCESS
    
    except BchocError as e:
        return e.exit_code
    
    except Exception as e:
        return ExitCode.ERROR
    
# handler for adding blocks to the blockchain
def add_handler(case_id: str, item_ids: List[int], creator: str, password: str) -> int:
    try:
        if not validate_password(password, "CREATOR"):
            raise BchocError(ExitCode.ERROR, "Invalid Password.")
        
        if not validate_uuid(case_id):
            raise BchocError(ExitCode.ERROR, "Invalid Case ID.")
        
        for item_id in item_ids:
            if item_exists(item_id):
                raise BchocError(ExitCode.ERROR, "This item already exists.")
            
            if not validate_item_id(item_id):
                raise BchocError(ExitCode.ERROR, "Invalid Item ID")
            
            case_uuid = UUID(case_id)
            encrypted_case_id = cryptography.encrypt_id(case_uuid.bytes.ljust(32, b'\x00'))
            item_id_bytes = item_id.to_bytes(4, 'big').ljust(32, b'\x00')
            encrypted_item_id = cryptography.encrypt_id(item_id_bytes)
            prev_block_bytes = get_last_block_bytes()
            if prev_block_bytes is None:
                raise BchocError(ExitCode.ERROR, "Blockchain has not been intialized.")

            block_bytes = pack_block(
                prev_hash=cryptography.compute_block_hash(prev_block_bytes),
                timestamp=utc_epoch(),
                case_id=encrypted_case_id,
                item_id=encrypted_item_id,
                state=b'CHECKEDIN\x00\x00\x00',
                creator=creator.encode('utf-8').ljust(12, b'\x00'),
                owner = b'\x00' * 12,
                data=b''
            )

            add_block(block_bytes)

        return ExitCode.SUCCESS
    
    except BchocError as e:
        return e.exit_code
    
    except Exception as e:
        return ExitCode.ERROR

# handler to record when an evidence item is checked out
def checkout_handler(item_id: int, password: str) -> int:
    try:
        if not validate_password(password, "OWNER"):
            raise BchocError(ExitCode.ERROR, "Invalid password")
        
        if not item_exists(item_id):
            raise BchocError(ExitCode.ERROR, "Evidence item not found.")
        
        if not validate_item_id(item_id):
            raise  BchocError(ExitCode.ERROR, "Invalid item ID")
        
        if not checkout_allowed(item_id):
            state = get_item_state(item_id)
            raise BchocError(ExitCode.ERROR, "Item cannot be checked out in its current state.")
        
        encrypted_case_id = get_item_case_id(item_id)
        item_id_bytes = item_id.to_bytes(4, 'big').ljust(32, b'\x00')
        encrypted_item_id = cryptography.encrypt_id(item_id_bytes)

        last_block_bytes = get_last_block_bytes()
        if last_block_bytes is None:
            raise BchocError(ExitCode.ERROR, "Blockchain has not been intialized yet.")
        
        owner_role = validate_password_role(password, "OWNER")
        owner_bytes = owner_role.encode('utf-8').ljust(12, b'\x00')
        creator_bytes = get_item_creator(item_id)
        
        block_bytes = pack_block(
            prev_hash=cryptography.compute_block_hash(last_block_bytes),
            timestamp=utc_epoch(),
            case_id=encrypted_case_id,
            item_id=encrypted_item_id,
            state=b'CHECKEDIN\x00\x00',
            creator=creator_bytes,
            owner=owner_bytes,
            data=b''
        )
        add_block(block_bytes)
        return ExitCode.SUCCESS
    
    except BchocError as e:
        return e.exit_code
    
    except Exception as e:
        return ExitCode.ERROR
    
# handler for adding checkedin events
def checkin_handler(item_id: int, password: str) -> int:
    try:
        if not validate_password(password, "OWNER"):
            raise BchocError(ExitCode.ERROR, "Invalid password")
        
        if not item_exists(item_id):
            raise BchocError(ExitCode.ERROR, "Evidence item not found.")
        
        if not validate_item_id(item_id):
            raise  BchocError(ExitCode.ERROR, "Invalid item ID")
        
        if not checkout_allowed(item_id):
            state = get_item_state(item_id)
            raise BchocError(ExitCode.ERROR, "Item cannot be checked out in its current state.")
        
        encrypted_case_id = get_item_case_id(item_id)
        item_id_bytes = item_id.to_bytes(4, 'big').ljust(32, b'\x00')
        encrypted_item_id = cryptography.encrypt_id(item_id_bytes)

        last_block_bytes = get_last_block_bytes()
        if last_block_bytes is None:
            raise BchocError(ExitCode.ERROR, "Blockchain has not been intialized yet.")
        
        owner_role = validate_password_role(password, "OWNER")
        owner_bytes = owner_role.encode('utf-8').ljust(12, b'\x00')
        creator_bytes = get_item_creator(item_id)
        
        block_bytes = pack_block(
            prev_hash=cryptography.compute_block_hash(last_block_bytes),
            timestamp=utc_epoch(),
            case_id=encrypted_case_id,
            item_id=encrypted_item_id,
            state=b'CHECKEDOUT\x00\x00',
            creator=creator_bytes,
            owner=owner_bytes,
            data=b''
        )
        add_block(block_bytes)
        return ExitCode.SUCCESS
    
    except BchocError as e:
        return e.exit_code
    
    except Exception as e:
        return ExitCode.ERROR

# handler for displaying all sorted case_ids
def show_cases_handler(password: str) -> List[str]:
    if not validate_password(password, "OWNER"):
        raise BchocError(ExitCode.ERROR, "Invalid password/Higher clearance needed")
    
    case_ids = sort_cases(password)
    return case_ids

# handler for displaying all items in a specific case
def show_items_handler(case_id: str, password: str) -> List[int]:
    if not validate_uuid(case_id):
        raise BchocError(ExitCode.ERROR, "Invalid case ID.")
    
    if not validate_password(password, "OWNER"):
        raise BchocError(ExitCode.ERROR, "Invalid password/Higher clearance needed.")
    
    item_ids = sort_case_items(case_id)
    return item_ids

def show_history_handler(case_id: Optional[str], item_id: Optional[int], num_entries: Optional[int], reverse: bool, password: str) -> List[dict]:
    if not validate_password(password, "OWNER"):
        raise BchocError(ExitCode.ERROR, "Invalid password/Higher clearance required.")
    
    if case_id is not None and not validate_uuid(case_id):
        raise BchocError(ExitCode.ERROR, "Invalid case ID.")
    
    if item_id is not None and not validate_item_id(item_id):
        raise BchocError(ExitCode.ERROR, "Invalid item ID.")
    
    if (num_entries is not None) and (not isinstance(num_entries, int) or (num_entries <= 0)):
        raise BchocError(ExitCode.ERROR, "Number of entries is invalid.")
    
    history = get_block_history(case_id, item_id, num_entries, reverse)
    return history
    
# handler for removing evidence items from the blockchain
def remove_handler(item_id: int, reason:str, owner: Optional[str], password: str) -> int:
    try:
        if not validate_password(password, "CREATOR"):
            raise BchocError(ExitCode.ERROR, "Invalid password")
        
        if not item_exists(item_id):
            raise BchocError(ExitCode.ERROR, "Evidence item not found.")
        
        if not validate_item_id(item_id):
            raise BchocError(ExitCode.ERROR, "Invalid item ID.")
        
        if not validate_removal_reason(reason):
            raise BchocError(ExitCode.ERROR, "Invalid removal reason.")
        
        if not remove_allowed(item_id):
            raise BchocError(ExitCode.ERROR, "Cannot remove item in its current state.")
        
        encrypted_case_id = get_item_case_id(item_id)
        item_id_bytes = item_id.to_bytes(4, 'big').ljust(32, b'\x00')
        encrypted_item_id = cryptography.encrypt_id(item_id_bytes)

        last_block_bytes = get_last_block_bytes()
        if last_block_bytes is None:
            raise BchocError(ExitCode.ERROR, "Blockchain has not been intialized yet.")
        
        owner_bytes = b'\x00' * 12
        if reason == "RELEASED" and owner: # who the evidence was released to
            owner_bytes = owner.encode('utf-8').ljust(12, b'\x00')

        creator_bytes = get_item_creator(item_id)
        state_bytes = reason.encode('utf-8').ljust(12, b'\x00')
        
        block_bytes = pack_block(
            prev_hash=cryptography.compute_block_hash(last_block_bytes),
            timestamp=utc_epoch(),
            case_id=encrypted_case_id,
            item_id=encrypted_item_id,
            state=state_bytes,
            creator=creator_bytes,
            owner=owner_bytes,
            data=b''
        )
        add_block(block_bytes)
        return ExitCode.SUCCESS
    
    except BchocError as e:
        return e.exit_code
    
    except Exception as e:
        return ExitCode.ERROR
    
# handler for summarizing the total number of evidence items in a case + as well as record of states or current/previous items
def summary_handler(case_id: str) -> dict:
    if not validate_uuid(case_id):
        raise BchocError(ExitCode.ERROR, "Invalid case ID.")
    
    summary = get_case_summary(case_id)
    return summary

# handler for verifying the blockchain
def verify_handler():
    result = verify_chain()
    return result