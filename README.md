# Sawtooth::Sdk

Welcome to your new gem! In this directory, you'll find the files you need to be able to package up your Ruby library into a gem. Put your Ruby code in the file `lib/sawtooth/sdk`. To experiment with that code, run `bin/console` for an interactive prompt.

TODO: Delete this and the text above, and describe your gem


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'sawtooth-sdk'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install sawtooth-sdk

## Usage


### Setup Sawtooth Core

Follow instruction at https://sawtooth.hyperledger.org/docs/core/releases/latest/app_developers_guide/installing_sawtooth.html

### Setup libsecp256k1

$ git clone https://github.com/bitcoin-core/secp256k1.git && cd secp256k1
$ ./autogen.sh
$ ./configure --enable-module-recovery
$ make
$ sudo make install


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).


## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/sawtooth-sdk. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Code of Conduct

Everyone interacting in the Sawtooth::Sdk project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/sawtooth-sdk/blob/master/CODE_OF_CONDUCT.md).
