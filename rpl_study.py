from pathlib import Path
from copy import deepcopy
from statistics import mean
import argparse
import csv
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path.cwd()
TEST = ROOT / "tests/14-rpl-lite"

NEIGH = ROOT / "os/net/routing/rpl-lite/rpl-neighbor.c"
MRHOF = ROOT / "os/net/routing/rpl-lite/rpl-mrhof.c"
ICMP = ROOT / "os/net/routing/rpl-lite/rpl-icmp6.c"
CONF = TEST / "code/project-conf.h"
SENDER = TEST / "code/sender-node.c"
SINK = TEST / "code/root-node.c"

SIM = TEST / "11-gps-campaign.csc"
LOG = TEST / "COOJA.testlog"
CSV = ROOT / "rpl_campaign_v2.csv"
ERR = ROOT / "rpl_campaign_error.log"

SOURCES = (NEIGH, MRHOF, ICMP, CONF, SENDER, SINK)

SEEDS = range(1, 6)
SIZES = (8, 16)

MODES = ("baseline", "tuned", "guarded")
SCENARIOS = (
    "normal",
    "rank_pulse",
    "rank_pulse_w30",
    "rank_pulse_w120",
    "rank_persistent",
    "link_failure",
    "legitimate_change",
)

# Node 2 is moved here at t=400 in legitimate_change. It must create a
# clearly better legitimate parent; verify with --pilot before the campaign.
LEGIT_POS = (15, 0)

# Attribute attack DIOs to node 3 via the IPv6 source address low byte.
# Set False if the build fails on this macro (then counting is as in v1).
ATTACK_SRC_LOG = True

PULSE_STARTS = (360, 500, 640)


def pulse_width(scenario):
    return {"rank_pulse": 60, "rank_pulse_w30": 30,
            "rank_pulse_w120": 120}.get(scenario)


def event_window(scenario):
    width = pulse_width(scenario)
    if scenario == "link_failure":
        return 400, 680
    if scenario == "legitimate_change":
        return 400, 950
    if width:
        return 360, PULSE_STARTS[-1] + width + 50
    return 360, 950

FIELDS = (
    "mode", "scenario", "nodes", "seed",
    "sent", "received", "pdr",
    "event_sent", "event_received", "event_pdr",
    "post_pdr",
    "all_switches_after_event",
    "client_switches_after_event",
    "attack_dio_sent",
    "attack_dio_seen_client",
    "guard_hold", "guard_confirm",
    "first_client_switch_delay_s",
    "first_delivery_delay_s",
    "interpretation_flag",
)


def require_one(source, marker, context):
    count = source.count(marker)
    if count != 1:
        raise RuntimeError(
            f"Unexpected {context}: {count} matches"
        )


def git_original(path):
    relative = path.relative_to(ROOT).as_posix()
    return subprocess.check_output(
        ["git", "show", "HEAD:" + relative],
        cwd=ROOT,
    )


def patch_mrhof(mode, originals):
    source = originals[MRHOF].decode()

    if mode == "tuned":
        rank = "#define RANK_THRESHOLD 192"
        timing = (
            "#define TIME_THRESHOLD "
            "(10 * 60 * CLOCK_SECOND)"
        )

        require_one(source, rank, "Rank threshold")
        require_one(source, timing, "Time threshold")

        source = source.replace(
            rank,
            "#define RANK_THRESHOLD 512",
            1,
        )

        source = source.replace(
            timing,
            "#define TIME_THRESHOLD "
            "(15 * 60 * CLOCK_SECOND)",
            1,
        )

    MRHOF.write_text(source)

    if mode == "guarded":
        NEIGH.write_bytes(originals[NEIGH])
    else:
        NEIGH.write_bytes(git_original(NEIGH))


def patch_icmp(scenario, originals):
    source = originals[ICMP].decode()

    # Instrument rank advertisements received at client 2.
    marker = "  dio.rank = get16(buffer, i);"
    require_one(source, marker, "DIO input")

    receive_log = r'''
  if(node_id == 2 &&
     dio.rank == RPL_MIN_HOPRANKINC &&
     clock_seconds() >= 360) {
    LOG_INFO("GPS_ATTACK_RX rank=%u src=%u\n",
             (unsigned)dio.rank,
             (unsigned)UIP_IP_BUF->srcipaddr.u8[15]);
  }'''
    if not ATTACK_SRC_LOG:
        receive_log = receive_log.replace(
            "UIP_IP_BUF->srcipaddr.u8[15]", "0")

    source = source.replace(
        marker, marker + receive_log, 1
    )

    if scenario.startswith("rank_"):
        marker = (
            "  set16(buffer, pos,\n"
            "        rpl_get_leaf_only() ? "
            "RPL_INFINITE_RANK : curr_instance.dag.rank);"
        )
        require_one(source, marker, "DIO output")

        if pulse_width(scenario):
            w = pulse_width(scenario)
            condition = " || ".join(
                f"(t >= {a} && t < {a + w})"
                for a in PULSE_STARTS
            )
        else:
            condition = "t >= 360"

        injected = r'''
  {
    uint16_t advertised =
      rpl_get_leaf_only() ?
      RPL_INFINITE_RANK : curr_instance.dag.rank;

    unsigned long t = clock_seconds();

    if(node_id == 3 && (CONDITION)) {
      advertised = curr_instance.min_hoprankinc;
      LOG_INFO("GPS_ATTACK rank=%u\n",
               (unsigned)advertised);
    }

    set16(buffer, pos, advertised);
  }'''.replace("CONDITION", condition)

        source = source.replace(
            marker, injected, 1
        )

    include = '#include "lib/random.h"'
    require_one(source, include, "ICMP includes")

    source = source.replace(
        include,
        include
        + '\n#include "sys/node-id.h"'
        + '\n#include "sys/clock.h"',
        1,
    )

    ICMP.write_text(source)


def patch_transport(originals):
    source = originals[SENDER].decode()

    target = (
        "      message_number++;\n"
        "      simple_udp_sendto"
    )
    require_one(source, target, "Sender counter")

    replacement = (
        '      printf("GPS_TX seq=%u\\n", '
        'message_number);\n'
        "      message_number++;\n"
        "      simple_udp_sendto"
    )

    source = source.replace(
        target, replacement, 1
    )

    source, changes = re.subn(
        r'(#define\s+SEND_INTERVAL\s+)'
        r'\(60 \* CLOCK_SECOND\)',
        r'\g<1>(20 * CLOCK_SECOND)',
        source,
        count=1,
    )

    if changes != 1:
        raise RuntimeError("Sender interval mismatch")

    SENDER.write_text(source)

    source = originals[SINK].decode()
    target = '  printf("Data received from ");'
    require_one(source, target, "Root receiver")

    receiver_log = r'''
  unsigned int gps_seq;

  if(sscanf((const char *)data,
            "Message %u", &gps_seq) == 1) {
    printf("GPS_RX seq=%u\n", gps_seq);
  }

  printf("Data received from ");'''

    SINK.write_text(
        source.replace(target, receiver_log, 1)
    )


BASE = {
    1: (0, 0),
    2: (105, 0),
    3: (85, 25),
    4: (35, 0),
    5: (70, 0),
}

EXTRAS = [
    (25, -25), (50, -27), (82, -25),
    (20, 27), (46, 30), (74, 34),
    (103, 35), (30, 55), (56, 57),
    (84, 57), (110, 58),
]


def make_sim(scenario, count):
    event_start = event_window(scenario)[0]
    tree = ET.parse(
        TEST / "09-rpl-probing.csc"
    )

    simulation = tree.find(".//simulation")
    types = simulation.findall("motetype")

    if len(types) != 3:
        raise RuntimeError("Cooja template changed")

    existing = {
        int(mote.find(".//id").text): mote
        for kind in types
        for mote in kind.findall("mote")
    }

    for node_id, (x, y) in BASE.items():
        if node_id not in existing:
            continue

        position = existing[node_id].find(".//pos")
        position.set("x", str(x))
        position.set("y", str(y))

    template = types[2].find("mote")

    for node_id in range(4, count + 1):
        if node_id in BASE:
            x, y = BASE[node_id]
        else:
            x, y = EXTRAS[node_id - 6]

        mote = deepcopy(template)
        mote.find(".//id").text = str(node_id)

        position = mote.find(".//pos")
        position.set("x", str(x))
        position.set("y", str(y))

        types[2].append(mote)

    radio = simulation.find("radiomedium")
    radio.find("success_ratio_rx").text = "0.95"

    events = ""

    if scenario == "link_failure":
        events = '''
GENERATE_MSG(400000, "route-fail");
GENERATE_MSG(680000, "route-restore");'''

    elif scenario == "legitimate_change":
        events = '''
GENERATE_MSG(400000, "better-route");'''

    script = r'''
var tx = {}, rx = {};
var switches = 0, clientSwitches = 0;
var attackSent = 0, attackSeen = 0;
var hold = 0, confirmed = 0;

EVENTS

GENERATE_MSG(950000, "study-finish");
TIMEOUT(960000);

while(true) {
  YIELD();

  if(msg.equals("route-fail")) {
    sim.getMoteWithID(5).getInterfaces()
       .getPosition()
       .setCoordinates(55, 35, 0);
  }

  if(msg.equals("route-restore")) {
    sim.getMoteWithID(5).getInterfaces()
       .getPosition()
       .setCoordinates(70, 0, 0);
  }

  if(msg.equals("better-route")) {
    sim.getMoteWithID(2).getInterfaces()
       .getPosition()
       .setCoordinates(LEGX, LEGY, 0);
  }

  if(msg.equals("study-finish")) {
    log.log("GPS_SUM switches=" + switches +
            " client_switches=" + clientSwitches +
            " injected=" + attackSent +
            " seen=" + attackSeen +
            " hold=" + hold +
            " confirmed=" + confirmed + "\n");

    var n = 0;
    for(var k in tx) {
      if(tx.hasOwnProperty(k)) n++;
    }

    if(n < 20) log.testFailed();
    else log.testOK();
  }

  var m = /^GPS_TX seq=(\d+)/.exec(msg);

  if(id == 2 && m) {
    tx[m[1]] = time;
    log.log("GPS_TX," + m[1] +
            "," + time + "\n");
  }

  m = /^GPS_RX seq=(\d+)/.exec(msg);

  if(id == 1 && m) {
    rx[m[1]] = time;
    log.log("GPS_RX," + m[1] +
            "," + time + "\n");
  }

  if(msg.indexOf("parent switch:") >= 0 &&
     time >= EVSTART000000) {
    switches++;

    if(id == 2) {
      clientSwitches++;
      log.log("GPS_SWITCH," + time + "\n");
    }
  }

  if(msg.indexOf("GPS_ATTACK rank=") >= 0)
    attackSent++;

  if(msg.indexOf("GPS_ATTACK_RX rank=") >= 0 &&
     id == 2 && SRCCHECK)
    attackSeen++;

  if(msg.indexOf("GPS: candidate under") >= 0)
    hold++;

  if(msg.indexOf("GPS: candidate confirmed") >= 0)
    confirmed++;
}
'''.replace("EVENTS", events)
    script = script.replace("EVSTART", str(event_start))
    script = script.replace("LEGX", str(LEGIT_POS[0]))
    script = script.replace("LEGY", str(LEGIT_POS[1]))
    script = script.replace(
        "SRCCHECK",
        'msg.indexOf("src=3") >= 0' if ATTACK_SRC_LOG else "true",
    )

    runner = next(
        (
            plugin
            for plugin in tree.findall(".//plugin")
            if "ScriptRunner" in (plugin.text or "")
        ),
        None,
    )

    if runner is None:
        raise RuntimeError("Missing ScriptRunner")

    runner.find(".//script").text = script

    tree.write(
        SIM,
        encoding="utf-8",
        xml_declaration=True,
    )


def measure(content, scenario):
    transmitted = {}
    received = {}
    client_switches = []

    for line in content.splitlines():
        if (
            line.startswith("GPS_TX,")
            or line.startswith("GPS_RX,")
        ):
            event, sequence, timestamp = line.split(",")
            target = (
                transmitted
                if event == "GPS_TX"
                else received
            )
            target[int(sequence)] = (
                int(timestamp) / 1000000
            )

        elif line.startswith("GPS_SWITCH,"):
            client_switches.append(
                int(line.split(",")[1]) / 1000000
            )

    pattern = (
        r"GPS_SUM switches=(\d+) "
        r"client_switches=(\d+) "
        r"injected=(\d+) seen=(\d+) "
        r"hold=(\d+) confirmed=(\d+)"
    )

    match = re.search(pattern, content)

    if not match:
        raise RuntimeError("Missing Cooja summary")

    switches, client, attack, seen, hold, confirm = (
        map(int, match.groups())
    )

    delivered = {
        seq
        for seq in transmitted
        if seq in received
        and received[seq] >= transmitted[seq]
    }

    def delivery(start, end):
        offered = {
            seq
            for seq, timestamp in transmitted.items()
            if start <= timestamp < end
        }

        sent = len(offered)
        got = len(offered & delivered)

        ratio = (
            round(got / sent, 5)
            if sent else None
        )

        return sent, got, ratio

    sent, got, pdr = delivery(0, 950)

    event_start, event_end = event_window(scenario)

    event_sent, event_got, event_pdr = delivery(
        event_start, event_end
    )

    post_pdr = (
        delivery(680, 950)[2]
        if scenario == "link_failure"
        else None
    )

    first_switch = min(
        (
            t - event_start
            for t in client_switches
            if t >= event_start
        ),
        default=None,
    )

    first_delivery = min(
        (
            received[seq] - event_start
            for seq, timestamp in transmitted.items()
            if timestamp >= event_start
            and seq in delivered
            and received[seq] >= event_start
        ),
        default=None,
    )

    flags = []

    if scenario.startswith("rank_") and seen == 0:
        flags.append(
            "attack_not_observed_at_client"
        )

    if not event_sent:
        flags.append("no_event_packets")

    if got > sent:
        raise RuntimeError("Invalid PDR counters")

    return {
        "sent": sent,
        "received": got,
        "pdr": pdr,
        "event_sent": event_sent,
        "event_received": event_got,
        "event_pdr": event_pdr,
        "post_pdr": post_pdr,
        "all_switches_after_event": switches,
        "client_switches_after_event": client,
        "attack_dio_sent": attack,
        "attack_dio_seen_client": seen,
        "guard_hold": hold,
        "guard_confirm": confirm,
        "first_client_switch_delay_s": (
            round(first_switch, 2)
            if first_switch is not None else ""
        ),
        "first_delivery_delay_s": (
            round(first_delivery, 2)
            if first_delivery is not None else ""
        ),
        "interpretation_flag": ";".join(flags),
    }


def run_cooja(seed, scenario):
    LOG.unlink(missing_ok=True)

    command = [
        str(ROOT / "tools/cooja/gradlew"),
        "--no-watch-fs",
        "--parallel",
        "--build-cache",
        "-p", str(ROOT / "tools/cooja"),
        "run",
        "-Dslf4j.provider="
        "ch.qos.logback.classic.spi."
        "LogbackServiceProvider",
        "--args=--no-gui --contiki="
        + str(ROOT)
        + " --logdir=" + str(TEST)
        + " --random-seed=" + str(seed)
        + " " + str(SIM),
    ]

    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    content = (
        LOG.read_text(errors="replace")
        if LOG.exists() else ""
    )

    successful = (
        result.returncode == 0
        and "TEST OK" in content
        and "GPS_SUM" in content
    )

    if not successful:
        ERR.write_text(
            result.stdout[-16000:]
            + "\n" + result.stderr[-8000:]
            + "\n" + content[-10000:]
        )

        messages = ERR.read_text().splitlines()
        errors = [
            line for line in messages
            if any(
                token in line
                for token in (
                    "ERROR", "Caused by",
                    "Exception", "error:",
                    "FAILED", "Failed", "GPS_SUM",
                )
            )
        ]

        print(
            "\n".join(
                errors[-25:]
                if errors else messages[-25:]
            ),
            flush=True,
        )

        raise RuntimeError(
            f"Simulation failed: {ERR}"
        )

    return measure(content, scenario)


def write_csv(rows):
    if not rows:
        return

    with CSV.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=FIELDS
        )
        writer.writeheader()
        writer.writerows(rows)


def load_done():
    if not CSV.exists():
        return []
    with CSV.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        for k in ("nodes", "seed"):
            row[k] = int(row[k])
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true",
                    help="1 seed, 8 nodes only")
    ap.add_argument("--modes", default=",".join(MODES))
    ap.add_argument("--scenarios", default=",".join(SCENARIOS))
    ap.add_argument("--seeds", type=int, default=len(SEEDS))
    args = ap.parse_args()

    modes = args.modes.split(",")
    scenarios = args.scenarios.split(",")
    seeds = range(1, 2 if args.pilot else args.seeds + 1)
    sizes = (8,) if args.pilot else SIZES
    total = len(modes) * len(scenarios) * len(sizes) * len(seeds)

    if not (ROOT / "tools/cooja/build.gradle").is_file():
        raise SystemExit("Run from /workspaces/contiki-ng")

    original = {path: path.read_bytes() for path in SOURCES}

    if b"GPS_GUARD_BEGIN" not in original[NEIGH]:
        raise SystemExit("Guarded patch missing")

    rows = load_done()
    done = {(r["mode"], r["scenario"], r["nodes"], r["seed"])
            for r in rows}
    print(f"Resuming: {len(done)} runs already in {CSV}", flush=True)
    ERR.unlink(missing_ok=True)

    try:
        patch_transport(original)
        CONF.write_bytes(
            original[CONF]
            + b"\n#define RPL_CONF_DIO_INTERVAL_DOUBLINGS 2\n"
        )
        print(f"RPL CAMPAIGN: {total} Cooja simulations", flush=True)

        for mode in modes:
            patch_mrhof(mode, original)

            for scenario in scenarios:
                patch_icmp(scenario, original)

                for nodes in sizes:
                    make_sim(scenario, nodes)

                    for seed in seeds:
                        key = (mode, scenario, nodes, seed)

                        if key in done:
                            continue

                        print(f"[{len(rows)+1}] {mode} / {scenario} / "
                              f"{nodes} nodes / seed {seed}", flush=True)

                        metrics = run_cooja(seed, scenario)
                        rows.append({"mode": mode, "scenario": scenario,
                                     "nodes": nodes, "seed": seed,
                                     **metrics})
                        write_csv(rows)

                        print("PDR:", metrics["event_pdr"],
                              "Switches:",
                              metrics["all_switches_after_event"],
                              "Client:",
                              metrics["client_switches_after_event"],
                              "Attack seen:",
                              metrics["attack_dio_seen_client"],
                              flush=True)

    finally:
        for path, data in original.items():
            path.write_bytes(data)

        SIM.unlink(missing_ok=True)
        write_csv(rows)
        print(f"Saved {len(rows)} runs: {CSV}", flush=True)

    print("\nFINAL SUMMARY")
    print("=" * 70)

    for scenario in scenarios:
        for mode in modes:
            group = [
                row for row in rows
                if row["scenario"] == scenario
                and row["mode"] == mode
            ]

            if not group:
                continue

            pdr_values = [
                row["event_pdr"]
                for row in group
                if row["event_pdr"] is not None
            ]

            pdr = (
                round(mean(pdr_values), 4)
                if pdr_values else None
            )

            changes = mean(
                row["all_switches_after_event"]
                for row in group
            )

            print(
                scenario,
                mode,
                "PDR:", pdr,
                "Switches:", round(changes, 2),
                "Attack seen:",
                sum(
                    row["attack_dio_seen_client"]
                    for row in group
                ),
            )

    print("\nCAMPAIGN COMPLETED")


if __name__ == "__main__":
    main()
