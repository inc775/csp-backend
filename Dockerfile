FROM 4armed/ruby:latest
MAINTAINER Marc Wickenden <marc@4armed.com>

RUN echo 'gem: --no-rdoc --no-ri' >> $HOME/.gemrc && \
    gem install bundler && \
    bundle config path /remote_gems

WORKDIR /app
ADD Gemfile .
ADD Gemfile.lock .
ADD Procfile .
ADD config.ru .
RUN bundle install --deployment --without development test
ADD app.rb .

CMD ["bundle", "exec" , "foreman","start","-d","/app"]
