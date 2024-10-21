# frozen_string_literal: true

source "https://rubygems.org"

git_source(:github) {|repo_name| "https://github.com/#{repo_name}" }

# gem "rails"

# Added at 2018-09-04 09:23:37 +0200 by markus:
gem "ruby-debian", "~> 0.3.8", group: %i[build test]

# Added at 2018-09-05 09:02:15 +0200 by markus:
gem "ruby-xz", "~> 1.0", group: %i[build test]

# Added at 2018-09-07 13:10:19 +0200 by markus:
gem "bzip2-ffi", "~> 1.0", group: %i[build test]

# Added at 2018-09-07 16:41:14 +0200 by markus:
gem "test-unit", "~> 3.5", group: [:test]

gem "rspec", "~> 3.13", group: :test

gem "simplecov-lcov", "~> 0.8.0", group: :test

gem "simplecov", "~> 0.22.0", group: :test

gem "rspec-collection_matchers", "~> 1.2", group: :test

# Added at 2021-11-12 17:19:23 +0200 by bernhard:
gem 'parallel', '~> 1.20', '< 1.21', group: %i[build test]

# Added at 2018-12-05 19:28:10 +0100 by markus:
group :rubocop, optional: true do
  gem "rubocop", "~> 1.51.0"
  gem "rubocop-rspec", "~> 3.0"
end

gem "json-streamer", "~> 2.1"

group :development, optional: true do
  gem "byebug", "~> 11.1"
  gem "pry", "~> 0.14.2"
end

gem "feedjira", "~> 3.2", group: :monitor
