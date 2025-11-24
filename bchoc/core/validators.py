# Justin Guerrero - 1224417753
# The functions within this file are responsible for validating that input from the CLI is allowed
from uuid import UUID
import os

# validation check for uuid
def validate_uuid(uuid_string: str) -> bool:
    # check if input is empty or != str
    if not uuid_string or not (isinstance(uuid_string, str)):
        return False 
    
    try:
        UUID(uuid_string)
        return True
    except Exception:
        return False
    
    
# validate that password matches the environment passwords + the password is for someone with the clearance to complete an act
def validate_password(password: str, required_role: str) -> bool:
    # check the level of clearance needed an action 
    if (required_role == "CREATOR"):
        env_var = "BCHOC_PASSWORD_CREATOR"
        expected = os.environ.get(env_var)
        if expected is not None and password == expected:
            return True
    
    if (required_role == "OWNER"):
        roles = ["POLICE", "LAWYER", "ANALYST", "EXECUTIVE"]
        for role in roles:
            env_var = f"BCHOC_PASSWORD_{role}"
            expected = os.environ.get(env_var)
            if expected is not None and password == expected:
                return True
        return False
            
    return False

# validate that item_id is indeed a 4-byte int
def validate_item_id(item_id: int) -> bool:
    if not isinstance(item_id, int):
        return False
    
    if (item_id < 0) or (item_id > 0xFFFFFFFF):
        return False
    
    return True

# validate that state of evidence is acceptable
def validate_state(state: str) -> bool:
    states =["INITIAL", "CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"]
    if state in states:
        return True
    else:
        return False

# validate that reason for evidence removal is acceptable
def validate_removal_reason(reason: str) -> bool:
    reasons = ["DISPOSED", "DESTROYED", "RELEASED"]

    if reason in reasons:
        return True
    else:
        return False

# helper to get the role of user's password 
def validate_password_role(password: str, required_role: str) -> str:
    # check the level of clearance needed an action 
    if (required_role == "CREATOR"):
        env_var = "BCHOC_PASSWORD_CREATOR"
        expected = os.environ.get(env_var)
        if expected is not None and password == expected:
            return "CREATOR"
    
    if (required_role == "OWNER"):
        roles = ["POLICE", "LAWYER", "ANALYST", "EXECUTIVE"]
        for role in roles:
            env_var = f"BCHOC_PASSWORD_{role}"
            expected = os.environ.get(env_var)
            if expected is not None and password == expected:
                return role
            
    return ""

