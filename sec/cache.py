"""Remember ciphertext so an identical TCP retransmission can reuse it."""


class RetransmissionCache:
    def __init__(self, max_entries=10000):
        self.entries = {}
        self.max_entries = max_entries

    def _key(self, connection_id, direction, sequence_number, data_length):
        return connection_id, direction, sequence_number, data_length

    def get(self, connection_id, direction, sequence_number, plaintext):
        key = self._key(
            connection_id, direction, sequence_number, len(plaintext)
        )
        saved = self.entries.get(key)

        if saved is None:
            return None

        saved_plaintext, saved_ciphertext = saved
        if saved_plaintext != plaintext:
            raise ValueError("This TCP segment key has different data")

        return saved_ciphertext

    def store(
        self, connection_id, direction, sequence_number,
        plaintext, ciphertext
    ):
        key = self._key(
            connection_id, direction, sequence_number, len(plaintext)
        )
        saved = self.entries.get(key)

        if saved is not None:
            if saved[0] != plaintext:
                raise ValueError("Refusing to cache different data for this segment")
            return

        if len(self.entries) >= self.max_entries:
            raise RuntimeError("Cache is full")

        self.entries[key] = (plaintext, ciphertext)
