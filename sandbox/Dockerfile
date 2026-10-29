FROM gcc@sha256:5e927c284bf55a7dc796262e311a0703344f62f41f5621eb56843111b1d37e15 AS dependencies
USER 10001:10001
WORKDIR /tmp
COPY requirements.txt /tmp/assignment-requirements.txt
# Extract Debian packages as an ordinary user. No package installation scripts run.
RUN mkdir -p /tmp/deps && \
    curl --fail --location --proto '=https' --tlsv1.2 --max-time 90 \
      https://deb.debian.org/debian/pool/main/libp/libpcap/libpcap0.8_1.10.3-1_amd64.deb -o pcap.deb && \
    curl --fail --location --proto '=https' --tlsv1.2 --max-time 90 \
      https://deb.debian.org/debian/pool/main/libp/libpcap/libpcap0.8-dev_1.10.3-1_amd64.deb -o pcap-dev.deb && \
    curl --fail --location --proto '=https' --tlsv1.2 --max-time 90 \
      https://deb.debian.org/debian/pool/main/d/dbus/libdbus-1-3_1.14.10-1~deb12u1_amd64.deb -o dbus.deb && \
    dpkg-deb --extract pcap.deb /tmp/deps && \
    dpkg-deb --extract pcap-dev.deb /tmp/deps && \
    dpkg-deb --extract dbus.deb /tmp/deps
# pip.pyz is pypa's own rolling "latest pip" bootstrap bundle, so its hash
# changes on every pip release; this pins the hash seen when this Dockerfile
# was last updated (2026-10-29) as a check against a corrupted or tampered
# download, not as a long-term version pin. A future pip release will make
# the build fail closed here (sha256sum mismatch) rather than run an
# unverified artifact; update the hash from a fresh download when that happens.
RUN curl --fail --location --proto '=https' --tlsv1.2 --max-time 90 \
      https://bootstrap.pypa.io/pip/pip.pyz -o /tmp/pip.pyz && \
    echo 'e5ef64ef63ff89a746014ad81658b76c1940385fdcdbc4fcbfa6e3ef1887352d  /tmp/pip.pyz' | sha256sum -c - && \
    python3 /tmp/pip.pyz --isolated install --disable-pip-version-check \
      --no-cache-dir --only-binary=:all: --target /tmp/pythondeps \
      --requirement /tmp/assignment-requirements.txt

FROM gcc@sha256:5e927c284bf55a7dc796262e311a0703344f62f41f5621eb56843111b1d37e15
COPY --from=dependencies --chown=10001:10001 /tmp/deps /opt/assignment-deps
COPY --from=dependencies --chown=10001:10001 /tmp/pythondeps /opt/pythondeps
ENV PYTHONPATH=/opt/pythondeps
ENV C_INCLUDE_PATH=/opt/assignment-deps/usr/include
ENV LIBRARY_PATH=/opt/assignment-deps/usr/lib/x86_64-linux-gnu
ENV LD_LIBRARY_PATH=/opt/assignment-deps/usr/lib/x86_64-linux-gnu:/opt/assignment-deps/lib/x86_64-linux-gnu
USER 10001:10001
WORKDIR /work
