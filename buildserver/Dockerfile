# A custom docker build is needed to provide a working sshd for Vagrant provisioning

FROM debian:stretch

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive

RUN echo Etc/UTC > /etc/timezone \
	&& echo 'APT::Install-Recommends "0";' \
		'APT::Install-Suggests "0";' \
		'APT::Acquire::Retries "20";' \
		'APT::Get::Assume-Yes "true";' \
		'Dpkg::Use-Pty "0";' \
		'quiet "1";' \
        >> /etc/apt/apt.conf.d/99gitlab

# setup 'vagrant' user for compatibility
RUN useradd --create-home -s /bin/bash vagrant && echo -n 'vagrant:vagrant' | chpasswd

# the provision scripts must be run in the same order as in Vagrantfile
# - vagrant needs openssh-client iproute2 ssh sudo
# - ansible needs python3
RUN printf "path-exclude=/usr/share/locale/*\npath-exclude=/usr/share/man/*\npath-exclude=/usr/share/doc/*\npath-include=/usr/share/doc/*/copyright\n" >/etc/dpkg/dpkg.cfg.d/01_nodoc \
	&& mkdir -p /usr/share/man/man1 \
	&& apt-get update \
	&& apt-get upgrade \
	&& apt-get dist-upgrade \
	&& apt-get install openssh-client iproute2 python3 openssh-server sudo \
	&& apt-get autoremove --purge \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Vagrant sudo setup for compatibility
RUN echo 'vagrant ALL = NOPASSWD: ALL' > /etc/sudoers.d/vagrant \
	&& chmod 440 /etc/sudoers.d/vagrant \
	&& sed -i -e 's/Defaults.*requiretty/#&/' /etc/sudoers

# - Vagrant uses a public "insecure" key for bootstrapping, then replaces it
RUN	mkdir -p /home/vagrant/.ssh \
	&& chmod 700 /home/vagrant/.ssh \
	&& echo "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== vagrant_insecure_public_key" > /home/vagrant/.ssh/authorized_keys \
	&& chmod 600 /home/vagrant/.ssh/authorized_keys \
	&& chown -R vagrant:vagrant /home/vagrant/.ssh \
	&& sed -i -e 's/\(UsePAM \)yes/\1 no/' /etc/ssh/sshd_config \
	&& mkdir /var/run/sshd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
