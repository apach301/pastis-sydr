FROM sydr/ubuntu20.04-sydr-fuzz

# Install Python3.10
RUN apt install software-properties-common -y && \
    add-apt-repository --yes ppa:deadsnakes/ppa && \
    apt install -y python3.10 python3.10-distutils python3.10-dev && \
    rm /usr/bin/python3 && ln -s /usr/bin/python3.10 /usr/bin/python3

# Upgrade pip
RUN wget https://bootstrap.pypa.io/get-pip.py && python3 get-pip.py

# Install python dependencies
RUN pip install protobuf --upgrade

# Install pastis-framework
RUN pip install pastis-framework

# Install pastis-sydr
RUN mkdir /pastis
COPY . /pastis/pastis-sydr
RUN cd /pastis/pastis-sydr && pip install . && mv targets ../

# Download sydr-fuzz
# RUN curl ...

ENV PATH=/pastis/sydr:/pastis/pastis-sydr/bin:$PATH
ENV SYDR_PATH=/pastis/sydr
