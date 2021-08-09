FROM python:3

COPY config.yml.sample /config.yml
COPY gc-auto-resolver.py /
COPY Pipfile /
COPY Pipfile.lock /
COPY threat_feeds /threat_feeds
COPY guardicore /guardicore

WORKDIR /

RUN pip install --upgrade pip
RUN pip install pipenv
RUN pipenv install

CMD ["pipenv", "run", "python", "gc-auto-resolver.py"]