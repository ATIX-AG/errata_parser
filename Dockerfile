FROM ruby:2.5-stretch

LABEL maintainer="Markus Bucher <bucher@atix.de>"
LABEL description="This container includes the errata-parser for Debian and Ubuntu"

WORKDIR /errataparser

RUN apt-get update && apt-get install -y \
      build-essential \
      libapt-pkg-dev

COPY . .

RUN bundle install --deployment

VOLUME /errata

CMD bundle exec errata_parser.rb --config /errata/config.json --debian /errata/ --ubuntu /errata/ --metadata