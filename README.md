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

Please check the PGW test suite we have at
https://gitea.osmocom.org/ttcn3/osmo-ttcn3-hacks/src/branch/master/pgw
for a full example.  This test suite implements the signaling plane of
simulating UE/MME/SGW towards a PGW (device under test).  It uses
osmo-uecups to simulate the user plane and start commands like "ping"
within the netns of the simulated UE.

The interface between test suite and osmo-uecups is using
JSON-serialized commands via a SCTP socket on SCTP port 4268.

JSON Examples from the above PGW tests suite execution look like below.  You can find a pcap file containing this example communication in contrib/osmo-uecups-example.pcap

### Initial reset of state:

Request to osmo-uecups:
```
{"reset_all_state":{}}
```

Response from osmo-uecups:
```
{"reset_all_state_res": {"result": "OK"}}
```

### Creating a GTP tunnel / UE with its own tun-device in its own netns

Request to osmo-uecups:
```
{
   "create_tun" : {
      "local_gtp_ep" : {
         "Port" : 2152,
         "addr_type" : "IPV4",
         "ip" : "AC121B14"
      },
      "remote_gtp_ep" : {
         "Port" : 2152,
         "addr_type" : "IPV4",
         "ip" : "AC121B07"
      },
      "rx_teid" : 2029948341,
      "tun_dev_name" : "tun23",
      "tun_netns_name" : "tun23",
      "tx_teid" : 6,
      "user_addr" : "0A2D0003",
      "user_addr_type" : "IPV4"
   }
}
```

Response from osmo-uecups:
```
{"create_tun_res": {"result": "OK"}}
```

### Running a test program (here "ping") inside that netns, just as if the command was executed on the UE


Request to osmo-uecups:
```
{
   "start_program" : {
      "command" : "ping -c 10 -i 1 -I 10.45.0.3 10.45.0.1 1>>/data/TC_createSession_ping4.prog.stdout 2>>/data/TC_createSession_ping4.prog.stderr",
      "environment" : [],
      "run_as_user" : "osmocom",
      "tun_netns_name" : "tun23"
   }
}
```

Initial Response from osmo-uecups (program was started):
```
{"start_program_res": {"pid": 12, "result": "OK"}}
```

Final response from osmo-uecups (program terminated):
```
{"program_term_ind": {"exit_code": 0, "pid": 12}}
```



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

We use a Gerrit based patch submission/review process for managing
contributions.  Please see
https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit for
more details

The current patch queue for osmo-uecups can be seen at
https://gerrit.osmocom.org/#/q/project:osmo-uecups+status:open
