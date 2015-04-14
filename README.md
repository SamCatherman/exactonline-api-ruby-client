# Elmas

Elmas means diamond, but in this case it's an API wrapper for Exact Online.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'elmas'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install elmas

## Usage

You have to have an Exact Online account and an app setup to connect with.

You have to set a few env variables to make a connection possible. Copy the `.env.sample` file, edit it to match your credentials and save it as `.env`

Then configure Elmas like this

```ruby
client_params = {
  client_id: ENV['client_id'],
  client_secret: ENV['client_secret']
}

authorize_params = {
  user_name: ENV['user_name'],
  password: ENV['password']
}

client = Elmas::Client.new(client_params)
client.authorize(authorize_params)
#The client will now be authorized for 10 minutes,
# if there are requests the time will be reset,
# otherwise authorization should be called again.

unless client.authorized?
  client.authorize(authorize_params)
end
```

To find a contact

```ruby
contact = Elmas::Contact.new(id: "23445")
contact.find
```

To create a new contact

```ruby
contact = Elmas::Contact.new(first_name: "Karel", last_name: "Appel", id: "2378712")
contact.save
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release` to create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

1. Fork it ( https://github.com/[my-github-username]/elmas/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Hoppinger

This gem was created by [Hoppinger](https://www.hoppinger.com)
