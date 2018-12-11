module Sawtooth
  module Signing
    module Base
      # A public key instance.
      #
      # The underlying content is dependent on implementation.
      class PublicKey

        def initialize
          raise NotImplementedError
        end

        # Returns the algorithm name used for this public key.
        def algorithm_name
          raise NotImplementedError
        end

        # Return the private key encoded as a hex string.
        def as_hex
          raise NotImplementedError
        end

        # Return the private key bytes.
        def as_bytes
          raise NotImplementedError
        end

      end
    end
  end
end