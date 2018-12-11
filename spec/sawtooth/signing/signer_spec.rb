require 'sawtooth'

RSpec.describe Sawtooth::Signing::Signer do
  # NOTE: signature from sawtooth java
  # 
  # let(:private_key_hex) { '80378f103c7f1ea5856d50f2dcdf38b97da5986e9b32297be2de3c8444c38c08' }
  # let(:public_key_hex) { '0279b0fbdf73d8656c86ef6fe12c5de883ebb5a07126aa2ab655e6f8321cb4beed' }
  # let(:message) { 'Hello, Alice, this is Bob' }
  # let(:message_signature) { 'b7eec6dc1e4c3b64f0d5bae3f0e6be3978120c69ea1c8b5987921a869f36cb262a4200527f9a06585a4d461281e008b929f7c4ec24880d2baf2a774cfc61969a' }

  let(:private_key_hex) { '86bcc5485166e49e2e7815de6d8f408beaaa6983d98df04fed033618f375e8af' }
  let(:private_key) { Sawtooth::Signing::Secp256k1::Secp256k1PrivateKey.from_hex(private_key_hex) }
  let(:public_key_hex) { '047a3ac999e93af3010dfbd2554af29cca965340924a2409876dabd76eb43212b74813485fcf5d806dae9ddced97c4be394f994b460e454b557b125e15d44a61fd' }
  let(:public_key) { Sawtooth::Signing::Secp256k1::Secp256k1PublicKey.from_hex(public_key_hex) }
  let(:context) { Sawtooth::Signing::Core.create_context('secp256k1') }
  let(:signer) { Sawtooth::Signing::Signer.new(context, private_key) }
  let(:message) { 'Hello, Alice, this is Bob' }
  let(:message_signature) { '3045022100ef389f537e809bef4af9daeb4265dd01f282831ef430d2bdfcd87fca44a2de5002205b7e89618e25fb0693c8bdcfd0a60a7a4d836e595edd1df1904791a6e38bf125' }

  describe "#sign" do
    it "should return different message_signature everytime" do
      first_message_signature = signer.sign(message)
      second_message_signature = signer.sign(message)
      
      expect(first_message_signature).not_to eq second_message_signature
    end
  end

  describe "#verify" do
    it "should return true for matching signature" do
      expect(signer.verify(message_signature, message)).to be true
    end

    it "should return false for non-matching signature" do
      expect(signer.verify(message_signature, message + '1')).to be false
    end

    it "#sign and #verify its own signatures should return true" do
      adhoc_message = 'Adhoc Message'
      adhoc_message_signature = signer.sign(adhoc_message)
      expect(signer.verify(adhoc_message_signature, adhoc_message)).to be true
    end

    it "#verify modified signatures should return false" do
      adhoc_message = 'Adhoc Message'
      adhoc_message_signature = signer.sign(adhoc_message)
      expect(signer.verify(adhoc_message_signature, adhoc_message + '1')).to be false
    end
  end

  describe "#public_key" do
    it "should return public key instance" do
      expect(signer.public_key).to be_instance_of Sawtooth::Signing::Secp256k1::Secp256k1PublicKey
      expect(signer.public_key.as_hex).to eq public_key_hex
    end
  end
end