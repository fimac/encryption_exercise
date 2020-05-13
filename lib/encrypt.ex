defmodule Encrypt do
  @moduledoc """
  Documentation for `Encrypt`.
  """

  @aad "AES128CBC"

  @doc """
  `generate_secret`
  Generates a random base64 encoded secret key
  :crypto.strong_rand_bytes(16) -> generates a binary composed of 16 random bytes
  then that is encoded into base 64.

  secret = Encrypt.generate_secret
  "PDfynjKNKUMcqBNQZwx3tQ=="

  We can store this as an environment variable.
  """

  def generate_secret do
    :crypto.strong_rand_bytes(16)
    |> :base64.encode()
  end

  @doc """
  Uses erlangs block encrypt/4.
  - Mode of encryption
  - The secret key
  - The initialisation vector
  - The string we want to encrypt.

  It returns a tuple {ciphertext, ciphertag}
  ciphertext -> this is the encrypted version of our original plain text.
  ciphertag -> is the message authentication code (MAC). This confirms that the message
  came from the stated sender and has not changed.

  The MAC value protects both a message's data integrity as well as its authenticity,
  by allowing verifiers to detect any changes to the message content.
  """

  def encrypt(val, key) do
    mode = :aes_cbc
    secret_key = :base64.decode(key)
    # initialization vector
    # - adds randomises the input data. Without this, every time you encrypt the same string, you end up with the same ciphertext.
    # - Block encryption will encrypt data of an arbitrary length by splitting that data into blocks, each matching the block cipher's size
    # - With the iv, everytime an encryption happens, a diffrent random set of bytes is mixed with the first block of input data.
    # Then the cipher text from the first block, is added to the second block etc.
    iv = :crypto.strong_rand_bytes(16)
    {ciphertext, mac} = :crypto.block_encrypt(mode, secret_key, iv, {@aad, val})
    (iv <> mac <> ciphertext) |> :base64.encode()
  end

  def decrypt(ciphertext, key) do
    mode = :aes_cbc
    secret_key = :base64.decode(key)
    <<iv::binary-16, mac::binary-16, ciphertext::binary>> = :base64.decode(ciphertext)
    :crypto.block_decrypt(mode, secret_key, iv, {@aad, ciphertext, mac})
  end
end
