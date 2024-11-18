# To build the image:
#   docker build -t imapdedup .
# To run the image:
#   docker run -it --rm imapdedup --help
FROM python:3.12-slim

RUN python -m pip install hatch
RUN mkdir /app

WORKDIR /app

COPY pyproject.toml /app

RUN hatch dep show requirements > /app/requirements.txt && \
    python -m pip install -r /app/requirements.txt

COPY . /app

ENTRYPOINT [ "hatch", "run", "imapdedup" ]
CMD [ "--help" ]