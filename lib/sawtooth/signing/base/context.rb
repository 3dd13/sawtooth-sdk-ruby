module Sawtooth
  module Signing
    module Base
      # A context for a cryptographic signing algorithm.
      class Context

        def initialize
          raise NotImplementedError
        end

        # Returns the algorithm name used for this context.
        def algorithm_name
          raise NotImplementedError
        end

        # 
        # Sign a message
        # 
        # Given a private key for this algorithm, sign the given message bytes and return a hex-encoded string of the resulting signature.
        def sign(message, private_key)
          raise NotImplementedError
        end

        # Verifies that a signature of a message was produced with the associated public key.
        def verify(signature, message, public_key)
          raise NotImplementedError
        end

        # Produce a public key for the given private key.
        def get_public_key(private_key)
          raise NotImplementedError
        end

        # Generate a new random private key, based on the underlying algorithm.
        def new_random_private_key
          raise NotImplementedError
        end

      end
    end
  end
end

require 'sawtooth/signing/secp256k1/secp256k1_context'
require 'sawtooth/signing/secp256k1/secp256k1_private_key'
require 'sawtooth/signing/secp256k1/secp256k1_public_key'