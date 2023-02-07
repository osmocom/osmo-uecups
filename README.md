osmo-uecups - Osmocom UE simulation control/user plane separation
=================================================================

This repository contains a C-language implementation of a simulator for
the SGW/MME/UE side of GTP-U. It is part of the
[Osmocom](https://osmocom.org/) Open Source Mobile Communications
project.

This code is primarily intended to be used in testing of 2G/3G/4G GGSN and P-GW.

Every GTP tunnel (corresponding to a PDP context or EPC bearer) is terminated
in a local 'tun' device, which in turn is put into its own network namespace.

This means you can simulate any number of users / sessions / bearers on a single
machine without any routing nightmare.

The code only implements the user plane (GTP1U), and not the control plane like
GTP1C or GTP2C.  osmo-uecups-daemon exposes a JSON-over-SCTP protocol calleD UECUPS,
which allows any external control plane instance to add/remove tunnels in the
daemon

Homepage
--------

The official homepage of the project is
https://osmocom.org/projects/osmo-ggsn/wiki/osmo-uecups

GIT Repository
--------------

You can clone from the official osmo-uecups.git repository using

	git clone https://gitea.osmocom.org/cellular-infrastructure/osmo-uecups

There is a web interface at <https://gitea.osmocom.org/cellular-infrastructure/osmo-uecups>

Documentation
-------------

FIXME

Mailing List
------------

Discussions related to this software are happening on the
osmocom-net-gprs@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/osmocom-net-gprs for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.


Contributing
------------
Our coding standards are described at
https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards

We us a gerrit based patch submission/review process for managing
contributions.  Please see
https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit for
more details

The current patch queue for osmo-uecups can be seen at
https://gerrit.osmocom.org/#/q/project:osmo-uecups+status:open
