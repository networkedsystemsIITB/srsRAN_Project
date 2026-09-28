srsRAN Project
==============

[![Build Status](https://github.com/srsran/srsRAN_Project/actions/workflows/ccpp.yml/badge.svg?branch=main)](https://github.com/srsran/srsRAN_Project/actions/workflows/ccpp.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/7868/badge)](https://www.bestpractices.dev/projects/7868)

The srsRAN Project is a complete 5G RAN solution, featuring an ORAN-native CU/DU developed by [SRS](http://www.srs.io).

The solution includes a complete L1/2/3 implementation with minimal external dependencies. Portable across processor architectures, the software has been optimized for x86 and ARM. srsRAN follows the 3GPP 5G system architecture implementing the functional splits between distributed unit (DU) and centralized unit (CU). The CU is further disaggregated into control plane (CU-CP) and user-plane (CU-UP).

See the [srsRAN Project](https://www.srsran.com/) for information, guides and project news.

Build instructions and user guides - [srsRAN Project documentation](https://docs.srsran.com/projects/project).

Community announcements and support - [Discussion board](https://www.github.com/srsran/srsran_project/discussions).

Features and roadmap - [Features](https://docs.srsran.com/projects/project/en/latest/general/source/2_features_and_roadmap.html).

L4Span
------

This branch adds [L4Span](https://github.com/PrincetonUniversity/L4Span) (Wan & Jamieson, *L4Span: Spanning Congestion Signaling over NextG Networks for Interactive Applications*, CoNEXT 2025, [doi:10.1145/3768972](https://doi.org/10.1145/3768972)) to srsRAN 25.10. The original prototype is built on srsRAN 24.10.

A per-PDU-session MARK entity sits between GTP-U and SDAP in the CU-UP (`lib/mark`):

* It models each DRB's RLC queue from the DL SDUs it forwards and the DL data delivery status reports that the DU already sends over F1-U.
* From the predicted dequeue rate, it derives a marking probability for L4S (ECT(1)) and classic (ECT(0)) flows.
* It CE-marks DL UDP packets.
* It CE-marks DL classic (ECT(0)) TCP packets, so any ECN-capable TCP (RFC 3168 or AccECN) reacts (`dl_classic_tcp_mark`, on by default).
* It leaves DL L4S (ECT(1)) TCP packets unmarked and rewrites the AccECN feedback of their UL ACKs instead, so the sender sees congestion without waiting for the RAN round trip.

L4Span is disabled by default. When disabled, MARK is not created and the data path is unchanged. To enable it, add the `configs/l4span.yml` overlay:

    sudo ./gnb -c <base config>.yml -c l4span.yml

Set `log: mark_level: debug` to log every marking decision. The feedback period is the DU F1-U timer (`qos: f1u_du: backoff_timer`, 10 ms by default).

### Differences from the original implementation

Only the CU-UP part of the original is ported. Its unused M1/MR-U interface, time-series library, RLC and DU changes are left out. The algorithm and its constants are kept; each constant is a configuration key whose default is the original value. The behaviour differs in the following ways:

| Original (24.10) | This port |
|---|---|
| Always on | `cu_up: l4span: enabled`, off by default |
| Classic (ECT(0)) TCP signalled only through the UL AccECN rewrite, so RFC 3168 ECN senders never see it | Classic TCP is CE-marked on the DL and its ACKs are not rewritten; L4S TCP keeps the AccECN rewrite. `dl_classic_tcp_mark: false` restores the original |
| DU feedback handled on the UL executor | Handled on the UE DL executor, together with the DL path |
| L4S probability `(uint32_t)(req - pred + err) / 2 / err` truncates to an integer | `(req - pred + err) / (2 * err)`; the original is kept behind `legacy_l4s_prob_truncation` |
| Marking probability kept after all flows of a type go idle | 0 once no flow of that type was seen for `flow_idle_timeout_ms` |
| Non-ECT flows count as classic flows | Not counted |
| SDUs of unmapped QoS flows counted in the queue model | Not counted (SDAP drops them) |
| Queue model breaks at PDCP SN wrap-around | Modular SN arithmetic; resynchronises if feedback runs ahead of the model |
| Each `byte_buffer` segment parsed as a packet; 20-byte IPv4 header assumed | One packet per SDU; IP options, fragments and non-IPv4 handled (non-IPv4 passes through) |
| AccECN option always overwritten with 9 bytes | Only the fields present in the option are written |
| Full IP/TCP checksum recomputation | Incremental checksum update (RFC 1624) |
| First dequeue-rate sample is 0 | Measured from the ingress time of the first packet |
| Classic probability not capped | Capped at 1 |
| Flows never removed | Idle flows evicted |
| ACK rewrite breaks once a flow's TCP sequence numbers wrap (after 4 GiB) | Serial number arithmetic |
| `rand()` | Per-entity PRNG |

Build Preparation
-----------------

### Dependencies

* Build tools:
  * cmake:               <https://cmake.org/>
* Mandatory requirements:
  * libfftw:             <https://www.fftw.org/>
  * libsctp:             <https://github.com/sctp/lksctp-tools>
  * yaml-cpp:            <https://github.com/jbeder/yaml-cpp>
  * mbedTLS:             <https://www.trustedfirmware.org/projects/mbed-tls/>
* Optional requirements:
  * googletest:          <https://github.com/google/googletest/>
    * You can enable test building by using the cmake option `-DBUILD_TESTING=On`. GoogleTest is only mandatory when building with tests.

You can install the build tools and mandatory requirements for some example distributions with the commands below:

<details open>
<summary><strong>Ubuntu 22.04</strong></summary>

```bash
sudo apt-get install cmake make gcc g++ pkg-config libfftw3-dev libmbedtls-dev libsctp-dev libyaml-cpp-dev
```

</details>
<details>
<summary><strong>Fedora</strong></summary>

```bash
sudo yum install cmake make gcc gcc-c++ fftw-devel lksctp-tools-devel yaml-cpp-devel mbedtls-devel
```

</details>
<details>
<summary><strong>Arch Linux</strong></summary>

```bash
sudo pacman -S cmake make base-devel fftw mbedtls yaml-cpp lksctp-tools
```

</details>

#### Split-8

For Split-8 configurations, either UHD or ZMQ is required for the fronthaul interface. Both drivers are linked below, please see their respective documentation for installation instructions.

* UHD:                 <https://github.com/EttusResearch/uhd>
* ZMQ:                 <https://zeromq.org/>

#### Split-7.2

For Split-7.2 configurations no extra 3rd-party dependencies are required, only those listed above.

Optionally, DPDK can be installed for high-bandwidth low-latency scenarios. For more information on this, please see [this tutorial](https://docs.srsran.com/projects/project/en/latest/tutorials/source/dpdk/source/index.html#).

Build Instructions
------------------

Download and build srsRAN:

<details open>
<summary><strong>Vanilla Installation</strong></summary>

First, clone the srsRAN Project repository:

```bash
    git clone https://github.com/srsRAN/srsRAN_Project.git
```

Then build the code-base:

```bash
    cd srsRAN_Project
    mkdir build
    cd build
    cmake ../ 
    make -j $(nproc)
```

You can now run the gNB from ``srsRAN_Project/build/apps/gnb/``. If you wish to install the srsRAN Project gNB, you can use the following command:

```bash
    sudo make install
```

</details>

<details>
<summary><strong>ZMQ Enabled Installation</strong></summary>

Once ZMQ has been installed you will need build of srsRAN Project with the correct flags to enable the use of ZMQ.

The following commands can be used to clone and build srsRAN Project from source. The relevant flags are added to the ``cmake`` command to enable the use of ZMQ:

```bash
git clone https://github.com/srsran/srsRAN_Project.git
cd srsRAN_Project
mkdir build
cd build
cmake ../ -DENABLE_EXPORT=ON -DENABLE_ZEROMQ=ON
make -j $(nproc)
```

Pay extra attention to the cmake console output. Make sure you read the following line to ensure ZMQ has been correctly detected by srsRAN:

```bash
...
-- FINDING ZEROMQ.
-- Checking for module 'ZeroMQ'
--   No package 'ZeroMQ' found
-- Found libZEROMQ: /usr/local/include, /usr/local/lib/libzmq.so
...
```

</details>

<details>
<summary><strong>DPDK Enabled Installation</strong></summary>

Once DPDK has been installed and configured you will need to create a clean build of srsRAN Project to enable the use of DPDK.

If you have not done so already, download the code-base with the following command:

```bash
git clone https://github.com/srsRAN/srsRAN_Project.git
```

Then build the code-base, making sure to include the correct flags when running cmake:

```bash
cd srsRAN_Project
mkdir build
cd build
cmake ../ -DENABLE_DPDK=True -DASSERT_LEVEL=MINIMAL
make -j $(nproc)
```

</details>

### PHY Tests

PHY layer tests use binary test vectors and are not built by default. To enable, see the [docs](https://docs.srsran.com/projects/project/en/latest/user_manuals/source/installation.html).

Deploying srsRAN Project
------------------------

srsRAN Project can be run in two ways:

* As a monolithic gNB (combined CU & DU)
* With a split CU and DU

For exact details on running srsRAN Project in any configuration, see [the documentation](https://docs.srsran.com/projects/project/en/latest/user_manuals/source/running.html).

For information on configuring and running srsRAN for various different use cases,  check our [tutorials](https://docs.srsran.com/projects/project/en/latest/tutorials/source/index.html).
