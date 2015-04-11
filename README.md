# ThreatExchange

A ruby library to interface with Facebooks ThreatExchange API

## Installation

Add this line to your application's Gemfile:

    gem 'ThreatExchange'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ThreatExchange

## Usage

The ThreatExchange library has two objects you can instanciate queries and
submissions. To initialize either class you pass your access token in a hash into each object.

```ruby

config = { access_token: 'abc123' }
TE = ThreatExchange::Query.new(config)

```

To run a query you would first create a hash with the corespnding flags for example.
```ruby

 query = { 
    threat_type: 'COMPROMISED_CREDENTIAL',
	type: 'EMAIL ADDRESS',
	fields: 'indicator,passwords',
	limit: 30
}
```

Then we call the query 
```ruby

result = TE.threat_indicators(query)
```

The result will return as a hash and then from there you can manipulate as you like.

Each Query method matches the existing ThreatExchange API and supports the same parameters. 



TODO: Document / Test Submission


## Contributing

1. Fork it ( https://github.com/[my-github-username]/ThreatExchange/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
