import hashlib

class CustomHash:
    def __init__(self, hash_algorithm, state):
        self.hash_algorithm = hash_algorithm
        self._state = state

    def update(self, data):
        self._state.update(data)

    def hexdigest(self):
        return self._state.hexdigest()

    def digest(self):
        return self._state.digest()

    def __getattr__(self, attr):
        return getattr(self._state, attr)

def length_extension_attack(hash_algorithm, original_hash, original_data, extension_data):
    state = bytearray.fromhex(original_hash)

    hash_obj = CustomHash(hash_algorithm, getattr(hashlib, hash_algorithm)(state))
    hash_obj.update(extension_data)
    forged_hash = hash_obj.hexdigest()

    forged_data = original_data + b'\x80' + extension_data

    return forged_hash, forged_data

# Example usage
hash_algorithm = 'sha256'
original_hash = '6dcd64d6303624fce098b736d6f90e62b2f748f54f84a83f7e14a282dc1bbe98'
original_data = b'Mat ma hoc kho qua di'
extension_data = b'Kho thi bo di?'

forged_hash, forged_data = length_extension_attack(hash_algorithm, original_hash, original_data, extension_data)

print('Original Hash:', original_hash)
print('Forged Hash:', forged_hash)
