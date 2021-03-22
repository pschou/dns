ARG ARCH="amd64"
ARG OS="linux"
FROM scratch
LABEL description="Very simple DNS lookup utility, built in golang" owner="dockerfile@paulschou.com"

ADD ./LICENSE /LICENSE
ADD ./dns "/dns"
ENTRYPOINT  [ "/dns" ]
