require 'sawtooth'

RSpec.describe Sawtooth::Signing::Core do
  describe "#create_context" do
    it "should return context for valid algorithm name" do
      expect(Sawtooth::Signing::Core.create_context('secp256k1')).not_to be_nil
      expect(Sawtooth::Signing::Core.create_context('secp256k1')).to be_kind_of(Sawtooth::Signing::Base::Context)
    end

    it "should raise parse error for incorrect hex public key" do
      expect { Sawtooth::Signing::Core.create_context('invalid algo') }.to raise_error(Sawtooth::Signing::NoSuchAlgorithmError, 'unknown algorithm invalid algo')
    end
  end
end