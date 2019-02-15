FROM ubuntu:18.04

# Install Python.
RUN apt-get update \
  && apt-get install -y python3-pip python3-dev \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && pip3 install --upgrade pip
WORKDIR /service
#RUN python3 -m pip install --upgrade pip
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY . ./
EXPOSE 5000
ENTRYPOINT ["python3", "log_classification/controller.py"]