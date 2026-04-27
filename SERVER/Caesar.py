class Caesar:
  def __init__(self, key):
      self.key = key

  def caesar_cipher_bytes(self, data, key):
    # אנחנו משתמשים ב-modulo 256 כדי להישאר בטווח של בייט בודד
    return bytes([(b + key) % 256 for b in data])

  def caesar_decipher_bytes(self, data, key):
    return bytes([(b - key) % 256 for b in data])