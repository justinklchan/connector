source "https://rubygems.org"
ruby "2.0.0"
gem 'sinatra', '1.1.0'
gem 'sinatra-flash', :git => 'https://github.com/SFEley/sinatra-flash.git'
gem 'data_mapper', '1.2.0'
gem 'pony', '1.6.2'

group :production do
    gem "pg"
    gem "dm-postgres-adapter"
end

group :development, :test do
    gem "sqlite3"
    gem "dm-sqlite-adapter"
end