import struct
from typing import Tuple


# Responsibilities:
#   - Validate fixed-size fields before packing (sizes, padding)
#   - Serialize (pack) and deserialize (unpack) the binary on-disk format
#   - Allow to check if it is the genesis block

# It does not:
#   - Blockchain logic
#   - Cryptography 
#   - CLI / printing / formatting 

# https://docs.python.org/3/library/struct.html
# struct.pack(format_string, value1, value2...,)
# struct.unpack(format_string, buffer)


HEADER_FORMAT = "<32s d 32s 32s 12s 12s 12s I" # "<" makes this little endian
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
ZERO32 = b"\x00" * 32

# encodes a string to UTF-8 and returns n bytes. It will truncate or pad
# the string to make sure the field is correctly sized.
def pad_string(s: str, n: int) -> bytes:
    b = s.encode("utf-8")
    return (b[:n]).ljust(n, b"\x00")
    

class Block:
    prev_hash: bytes       # 32 bytes
    timestamp: float       # 8 bytes (double)
    case_id: bytes         # 32 bytes    already encrypted
    item_id: bytes         # 32 bytes    already encrypted
    state: str             # 12 bytes
    creator: str           # 12 bytes
    owner: str             # 12 bytes
    data_length: int       # 4 bytes 
    data: bytes            

    # checks if this is the genesis block
    def is_genesis(self) -> bool:
        return self.prev_hash == ZERO32 and self.timestamp == 0.0
    
    # pack the fixed-sized header with validated fields
    def pack_header(self) -> bytes:
         
         # make sure the sizes are correct
         if len(self.prev_hash) != 32:
              raise ValueError("prev_hash must be 32 bytes")
         if len(self.case_id) != 32:
              raise ValueError("case_id must be 32 bytes")
         if len(self.item_id) != 32:
              raise ValueError("item_id must be 32 bytes")
         
         # pad the strings if needed
         state_str   = pad_string(self.state,   12)
         creator_str = pad_string(self.creator, 12)
         owner_str   = pad_string(self.owner,   12)

         # calculate data length 
         data_len = len(self.data) if self.data is not None else 0
        
        # return the correctly padded header (no payload)
         return struct.pack(
              HEADER_FORMAT,
              self.prev_hash,
              self.timestamp,
              self.case_id,
              self.item_id,
              state_str,
              creator_str,
              owner_str,
              data_len
         )
    
    # return the correctly padded Block plus the data 
    def pack_block(self) -> bytes:
        header = self.pack_header()
        return header + (self.data or b"")
    
    @classmethod
    # unpack only the header and return a tuple of the fields
    # ( no data )
    def unpack_header(cls, header_bytes: bytes) -> Tuple[
        bytes, float, bytes, bytes, bytes, bytes, bytes, int]:
        if len(header_bytes) != HEADER_SIZE:
            raise ValueError(f"Header must be exactly {HEADER_SIZE} bytes")
        return struct.unpack(HEADER_FORMAT, header_bytes)
    
    @classmethod
    # unpacks a whole block and return a populated Block object with Python types
    def unpack_block(cls, block: bytes) -> "Block":
        if len(block) < HEADER_SIZE:
            raise ValueError("Block is shorter than header!")
         
        (prev_hash, timestamp, case_id, item_id, state_str, creator_str,
          owner_str, data_len) = cls.unpack_header(block[:HEADER_SIZE])   

        data = block[HEADER_SIZE:HEADER_SIZE + data_len]
        if len(data) != data_len:
             raise ValueError("OOps, length of data != data_length")
        
        def _strip_bytes(b: bytes) -> str:
             return b.split(b"\x00", 1)[0].decode("utf-8", errors="strict")
        
        obj = cls()
        obj.prev_hash = prev_hash
        obj.timestamp = timestamp
        obj.case_id = case_id
        obj.item_id = item_id
        obj.state = _strip_bytes(state_str)
        obj.creator = _strip_bytes(creator_str)
        obj.owner = _strip_bytes(owner_str)
        obj.data_length = data_len
        obj.data = data
        return obj

 