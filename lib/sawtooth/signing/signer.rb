module Sawtooth
  module Signing

    # A convenient wrapper of Context and PrivateKey
    class Signer

      def initialize(context, private_key)
        @context = context
        @private_key = private_key
        @public_key = nil
      end

      # Signs the given message.
      def sign(message)
        @context.sign(message, @private_key)
      end

      # Verifies the given hash against the given message.
      def verify(signature, message)
        @context.verify(signature, message, public_key)
      end

      # Return the public key for this Signer instance.
      def public_key
        @public_key ||= @context.get_public_key(@private_key)
      end
    end

  end
end
