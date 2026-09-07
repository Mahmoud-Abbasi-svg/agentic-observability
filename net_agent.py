"""A network observability agent: ask a question in plain language, it runs the diagnostics.

    python net_agent.py "why is github.com slow from here?"
    python net_agent.py                      # interactive, keeps context between questions
    python net_agent.py -v "is 8.8.8.8 up?"  # -v shows each tool call and its result

The agent decides which measurements to run and in what order, then reports what it found.
Tools come from net_tools.py and are all read-only - it can observe, never reconfigure.

TWO BACKENDS, same tools and same system prompt:

  cli  (default when no API key is set) drives the `claude` CLI already installed and logged
       in on this machine, so it needs no separate credential. The CLI cannot expose Python
       functions as native tools, so the model asks for them by emitting JSON, which this
       script parses and executes. Slightly less robust than native tool use - a malformed
       reply costs a retry - but it runs today at no extra cost.

  sdk  (default when ANTHROPIC_API_KEY is set) uses the Anthropic SDK's tool runner with
       native tool use. Cleaner and more reliable; needs an API key, billed separately.

Force one with --backend cli|sdk.
"""
from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Optional

import net_memory
import net_precision
import net_tools
import net_verify

MODEL = os.environ.get("NET_AGENT_MODEL", "claude-opus-5")
MAX_STEPS = 12          # measurements per question before the agent must conclude
MAX_TOKENS = 8000


def _supports_colour(stream) -> bool:
    """True only if dim text will actually render.

    cmd.exe does not interpret ANSI escapes unless virtual-terminal processing is switched on,
    so writing them unconditionally prints literal `<-[2m` noise around every trace line.
    Try to enable VT; if that fails, or output is redirected, emit plain text instead.
    """
    if os.environ.get("NO_COLOR") or not getattr(stream, "isatty", lambda: False)():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        return bool(kernel32.SetConsoleMode(
            handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:
        return False


DIM, RESET = ("\033[2m", "\033[0m") if _supports_colour(sys.stdout) else ("", "")

SYSTEM = """You are a network observability agent running on an operator's own machine. You \
answer questions about network behaviour by MEASURING, not by guessing.

How to work:

1. Establish the baseline before blaming anything remote. If a question implies broad failure \
("nothing works", "the internet is down"), check local_network first - a missing default \
gateway or an unreachable DNS server explains every downstream symptom at once.

2. Separate the layers, because they fail independently and users conflate them:
   name resolution -> reachability -> transport -> application.
   A name that will not resolve, a host that will not answer ICMP, a port that is closed, and \
a server returning 502 are four different faults with four different owners.

3. Do not treat ICMP loss as proof a host is down. Many networks drop ping while passing \
traffic. Confirm with tcp_latency on a port the host actually serves before concluding.

4. Prefer several cheap measurements over one expensive one. Request independent measurements \
together in the same step rather than one at a time. Keep ping counts and hop limits small \
unless a bigger sample is genuinely needed - traceroute in particular is slow.

5. Stop when the question is answered. Before each new measurement, ask yourself what result \
would change your answer; if nothing it could return would change it, do not take it. Three \
decisive measurements beat twelve thorough ones, and every extra one costs the operator time \
while they are waiting to act.

In particular, an UNDECIDABLE question is answered as soon as you have established what you \
can measure and identified what you cannot. Continuing to measure will not make it decidable. \
Establish the boundary, state it, and stop.

If you notice a real problem OUTSIDE what was asked, mention it in one line at the end - do \
not start investigating it. The operator asked one question; answer that one, and let them \
decide whether to ask about the other.

6. Compare against something. A latency number alone means little; the same measurement to a \
known-good reference host (1.1.1.1, 8.8.8.8) tells you whether the problem is the path to \
that one destination or this machine's connectivity in general.

7. Check the baseline tool before calling any number good or bad. It holds what past \
measurements of that host actually looked like on this machine, which is the only thing that \
makes "40 ms" meaningful - unremarkable for a distant host, alarming for the local gateway. \
But read what it reports about SAMPLE COUNT and TIME SPAN: a median over three samples from \
one afternoon is not a baseline, and presenting it as one is a guess dressed as a statistic. \
When there is little or no history, say so and fall back on comparison against a reference \
host. History accumulates as you measure, so an empty baseline is normal early on and is not \
itself a fault.

8. For "has this got worse / did something change", use detect_change, not your own eyeball \
comparison of two numbers. A percentage difference means nothing without knowing how much \
that particular path moves on its own: on a link that swings 20% between hours, a 12% rise is \
noise; on one stable to 2% it is an incident. detect_change measures that noise floor from \
the history itself and tells you which case you are in. Report its verdict as it stands - if \
it says a shift is not distinguishable from noise, do NOT then describe the shift as a \
degradation because the number happens to be higher. It also reports the smallest shift the \
current history could resolve; when a change is too small to call, say that, and say what \
more measurement would be needed.

9. Know the limits of your own instrument, and say so instead of implying an all-clear. A \
"no change detected" result means one of two very different things: nothing happened, or \
something happened that this setup could never have seen. Before reporting that a metric is \
unchanged - and especially when the user names a size they care about, like "has it got 10% \
worse" - call can_detect. It reports whether a change that size is even expressible here and \
which of three limits binds: the INSTRUMENT (ping reports whole milliseconds, so on a 2 ms \
gateway nothing under ~8% can be represented at all, and more sampling will never fix it), \
STATISTICS (the path's own variability at the current sample count), or COVERAGE (no full \
day-night cycle yet). Each has a different remedy, so name the one that binds. If a change of \
the size asked about is below the binding limit, say plainly: "I measured it, but my \
measurement is not precise enough to detect a change that small" - and give the remedy. Never \
let "I could not see it" be read as "it did not happen".

10. Check you were actually looking before describing the past. Any question about a past \
period - "was there a problem last night", "has it been slow this week" - needs coverage \
first. This machine sleeps, moves network and gets shut down, and the record has holes \
wherever that happened. A gap is NOT a quiet period: reasoning across one answers from the \
data on either side of a stretch nobody observed, and states it as confidently as a period \
that was fully covered. If the period was not observed, say so instead of characterising it.

11. Read the timeline before describing an outage. baseline summarises; it cannot tell 33 \
consecutive failed probes from 33 scattered ones, and "p95 loss 100%" has been read as \
"brief dropouts" when it was a half-hour outage. For any "was X down", "how long", "was the \
network healthy tonight" question, call availability: it lists the runs in order, with their \
length, whether they ended or measurement simply stopped, and whether every host failed \
together (the network) or one did (that host).

12. For "did the route change", "is the path different", or any latency rise on a host with \
history, call route_history before traceroute. One traceroute shows today's path and cannot \
say whether it is the usual one. Read its verdict as it stands: a route that ALTERNATES \
between paths is load balancing, not a change, and two traces that differ are not evidence \
of one. It also shows per-hop latency for the current path against its own history, which is \
what separates "the route changed" from "the same route got slower" - the two have different \
owners. It says WHERE a rise sits; whether the rise is real is still detect_change's call.

13. When you cannot resolve something, say what would. can_detect tells you the current setup \
is not precise enough; instrument_options tells you which of your instruments, if any, could \
be. It runs real measurements and takes tens of seconds, so use it when a resolution question \
is genuinely blocking an answer, not routinely. Note what it reports: an instrument's usable \
resolution is the WORSE of its step size and its run-to-run scatter, so a finer-grained tool \
does not help on a path whose readings scatter widely - and it says which of the two binds. If \
it recommends switching from ping to tcp_latency, pass on its caution: those measure different \
quantities, so a baseline built with one cannot be compared against the other.

Reporting:

- Lead with the answer, then the evidence that supports it. Quote the actual numbers you \
measured.
- Distinguish what you MEASURED from what you INFER. Say "I could not determine X" rather \
than presenting a guess as a finding - an operator acting on a confident wrong diagnosis is \
worse off than one told the data was inconclusive.
- A single sample is not a trend. If you measured once, say so rather than describing it as \
typical.
- If a measurement fails, that is itself data. Report it; do not silently drop it.
- Be concise. An operator wants the fault and the evidence, not a narration of every step."""

# net_memory.baseline reads stored history rather than touching the network, so it is a tool
# like any other but must never be recorded as a measurement of itself.
MEASUREMENT_TOOLS = {f.__name__: f for f in net_tools.ALL_TOOLS}
TOOLS = {**MEASUREMENT_TOOLS,
         "baseline": net_memory.baseline,
         "detect_change": net_memory.detect_change,
         "can_detect": net_memory.can_detect,
         "coverage": net_memory.coverage,
         "availability": net_memory.availability,
         "route_history": net_memory.route_history,
         "instrument_options": net_precision.instrument_options}


# --------------------------------------------------------------------------- tool execution

def run_tool(name: str, args: dict) -> str:
    """Execute one tool. Errors come back as TEXT, never raised - a failed probe is data, and
    an agent that sees the error message can correct itself instead of the run aborting.

    Successful measurements are appended to the history store, so every run makes the next
    one better informed.
    """
    fn = TOOLS.get(name)
    if fn is None:
        return f"No such tool {name!r}. Available: {', '.join(TOOLS)}"
    try:
        sig = inspect.signature(fn)
        bad = set(args) - set(sig.parameters)
        if bad:
            return (f"Tool {name} got unknown argument(s) {sorted(bad)}. "
                    f"Accepts: {list(sig.parameters)}")
        out = fn(**args)
    except net_tools.ToolError as e:
        return f"Tool rejected the request: {e}"
    except Exception as e:
        return f"Tool failed: {type(e).__name__}: {e}"
    if name in MEASUREMENT_TOOLS:
        net_memory.record(name, args, out)
    return out


def tool_catalogue() -> str:
    """Render the tool list for the CLI backend's prompt, straight from the signatures."""
    out = []
    for name, fn in TOOLS.items():
        sig = inspect.signature(fn)
        params = []
        for pname, p in sig.parameters.items():
            t = getattr(p.annotation, "__name__", "str")
            d = "" if p.default is inspect.Parameter.empty else f" (default {p.default!r})"
            params.append(f"{pname}: {t}{d}")
        doc = inspect.getdoc(fn) or ""
        out.append(f"* {name}({', '.join(params) or ''})\n"
                   + "\n".join("    " + l for l in doc.splitlines()))
    return "\n\n".join(out)


# --------------------------------------------------------------------------- CLI backend

CLAUDE_BIN = (os.environ.get("NET_AGENT_CLAUDE_BIN") or shutil.which("claude")
              or os.path.expanduser(r"~\AppData\Roaming\npm\claude.cmd"))

PROTOCOL = """You have these measurement tools available on the operator's machine:

{catalogue}

You cannot call them directly. Instead, reply with ONE JSON object and nothing else - no
prose outside it, no markdown fence. Either ask for measurements:

  {{"reasoning": "<one short line on why these>",
    "tool_calls": [{{"name": "ping", "args": {{"host": "1.1.1.1", "count": 3}}}}]}}

- put INDEPENDENT measurements in the same tool_calls list; they run together
- omit optional arguments to accept their defaults

or, once you have enough evidence, give the final answer:

  {{"reasoning": "<one short line>", "answer": "<your report to the operator>"}}

You have {remaining} measurement steps left. When they run out you must answer with what you
have, saying plainly what remained undetermined."""


def _claude_cli(prompt: str, timeout: int = 600) -> str:
    """One stateless call to the installed `claude` CLI.

    Three things here are load-bearing, learned the hard way:
      * the prompt goes on STDIN - passed as argv, cmd.exe mangles embedded quotes and the
        model silently receives a truncated prompt
      * `--tools ""` disables Claude Code's own tools, so it cannot wander off and read files
        or fetch URLs instead of answering with our protocol
      * `--output-format json` gives a parseable envelope; `.result` holds the text
    """
    if not (CLAUDE_BIN and (shutil.which(CLAUDE_BIN) or os.path.exists(CLAUDE_BIN))):
        raise RuntimeError("the `claude` CLI was not found; set NET_AGENT_CLAUDE_BIN")
    p = subprocess.run(
        [CLAUDE_BIN, "-p", "--model", MODEL, "--tools", "",
         "--system-prompt", SYSTEM, "--output-format", "json"],
        input=prompt, capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError(f"claude CLI exited {p.returncode}: {(p.stderr or '')[:300]}")
    try:
        return json.loads(p.stdout).get("result", p.stdout)
    except json.JSONDecodeError:
        return p.stdout


def _extract_json(text: str) -> dict | None:
    """Pull the outermost JSON object out of a reply, tolerating fences and stray prose."""
    if not text:
        return None
    text = re.sub(r"^\s*```(?:json)?|```\s*$", "", text.strip(), flags=re.M)
    depth, start = 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    start = None
    return None


def ask_cli(question: str, transcript: list[str], verbose: bool = False,
            trace: Optional[list] = None) -> str:
    """Agent loop over the `claude` CLI. `transcript` carries context across questions.

    If `trace` is given, each (tool_name, args) is appended to it - which tool the agent
    reached for is objective evidence about its reasoning, and the evaluation harness scores
    on it without needing to interpret prose.
    """
    steps: list[str] = []
    for step in range(MAX_STEPS):
        prompt = PROTOCOL.format(catalogue=tool_catalogue(), remaining=MAX_STEPS - step)
        if transcript:
            prompt += "\n\nEARLIER IN THIS SESSION:\n" + "\n".join(transcript[-6:])
        prompt += f"\n\nOPERATOR'S QUESTION: {question}\n"
        prompt += ("\n\nMEASUREMENTS SO FAR:\n" + "\n".join(steps)) if steps else \
                  "\n\nNo measurements taken yet."

        reply = _claude_cli(prompt)
        obj = _extract_json(reply)
        if obj is None:
            steps.append("[your last reply was not valid JSON - reply with one JSON object]")
            if verbose:
                print(f"  {DIM}!! unparseable reply, retrying{RESET}", flush=True)
            continue

        if obj.get("answer"):
            return str(obj["answer"])

        calls = obj.get("tool_calls") or []
        if not calls:
            steps.append("[your reply contained neither tool_calls nor answer]")
            continue
        for call in calls[:4]:
            name = str(call.get("name", ""))
            cargs = call.get("args") or {}
            if not isinstance(cargs, dict):
                cargs = {}
            if trace is not None:
                trace.append((name, dict(cargs)))
            if verbose:
                shown = ", ".join(f"{k}={v!r}" for k, v in cargs.items())
                print(f"  {DIM}-> {name}({shown}){RESET}", flush=True)
            result = run_tool(name, cargs)
            if verbose:
                head = result.splitlines()[0][:160] if result else ""
                print(f"  {DIM}<- {head}{RESET}", flush=True)
            steps.append(f"$ {name}({json.dumps(cargs)})\n{result}")
    return ("I ran out of measurement steps before reaching a conclusion. "
            "Measurements taken:\n\n" + "\n\n".join(steps[-3:]))


# --------------------------------------------------------------------------- SDK backend

def ask_sdk(messages: list, verbose: bool = False) -> str:
    """Native tool use via the SDK's tool runner. Needs ANTHROPIC_API_KEY."""
    import anthropic
    from anthropic import beta_tool

    def wrap(fn):
        def caller(**kwargs):
            return run_tool(fn.__name__, kwargs)
        caller.__name__ = fn.__name__
        caller.__doc__ = fn.__doc__
        caller.__annotations__ = getattr(fn, "__annotations__", {})
        caller.__signature__ = inspect.signature(fn)
        return beta_tool(caller)

    client = anthropic.Anthropic()
    runner = client.beta.messages.tool_runner(
        model=MODEL, max_tokens=MAX_TOKENS, system=SYSTEM,
        tools=[wrap(f) for f in TOOLS.values()], messages=messages)
    final = ""
    for message in runner:
        for block in message.content:
            if block.type == "text" and block.text.strip():
                final = block.text
            elif block.type == "tool_use" and verbose:
                args = ", ".join(f"{k}={v!r}" for k, v in block.input.items())
                print(f"  {DIM}-> {block.name}({args}){RESET}", flush=True)
        messages.append({"role": "assistant", "content": message.content})
        resp = runner.generate_tool_call_response()
        if resp is not None:
            messages.append(resp)
    return final


# --------------------------------------------------------------------------- CLI

def main() -> int:
    ap = argparse.ArgumentParser(description="Ask a network question; the agent measures.")
    ap.add_argument("question", nargs="*", help="the question (omit for interactive mode)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show each tool call and result")
    ap.add_argument("--backend", choices=["auto", "cli", "sdk"], default="auto",
                    help="auto uses the SDK when an API key is set, else the claude CLI")
    ap.add_argument("--no-verify", action="store_true",
                    help="do not check the answer's claims against each path's noise floor")
    args = ap.parse_args()

    # The model writes arrows, dashes and the odd non-Latin character, and a Windows console
    # that is not in UTF-8 raises on the first one - after the measurements were taken and
    # the answer composed. A whole diagnosis was lost that way to a single U+2192. Replace
    # what cannot be shown; never let the display decide whether the answer exists.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    backend = args.backend
    if backend == "auto":
        backend = "sdk" if (os.environ.get("ANTHROPIC_API_KEY")
                            or os.environ.get("ANTHROPIC_AUTH_TOKEN")) else "cli"
    if backend == "cli" and not (CLAUDE_BIN and (shutil.which(CLAUDE_BIN)
                                                 or os.path.exists(CLAUDE_BIN))):
        print("No API key and no `claude` CLI found. Either set ANTHROPIC_API_KEY or install\n"
              "Claude Code, or point NET_AGENT_CLAUDE_BIN at the binary.", file=sys.stderr)
        return 2

    transcript: list[str] = []
    sdk_messages: list = []

    def answer(q: str) -> str:
        if backend == "sdk":
            sdk_messages.append({"role": "user", "content": q})
            out = ask_sdk(sdk_messages, args.verbose)
        else:
            out = ask_cli(q, transcript, args.verbose)
            transcript.append(f"Q: {q}\nA: {out[:600]}")
        if args.no_verify:
            return out
        # Point 9 of SYSTEM asks the model never to let "I couldn't see it" read as "it didn't
        # happen". Asking is not enforcing: a prompt cannot stop a confident 4% claim on a path
        # whose floor is 20%. So every answer is re-checked against the same statistics the
        # monitor alerts on, in code, after the model has finished talking.
        #
        # The report is APPENDED, never substituted. Editing the model's words would hide the
        # disagreement, and the disagreement is the useful part.
        try:
            return net_verify.annotate(out, net_verify.verify(out))
        except Exception as e:
            # A broken verifier must not swallow the answer, but it must not pass silently
            # either - silence would read as "checked and clean".
            return f"{out}\n\n{'-' * 70}\nVERIFIER FAILED ({type(e).__name__}: {e}) - the " \
                   f"claims above are UNCHECKED."

    if args.question:
        try:
            print(answer(" ".join(args.question)))
        except Exception as e:
            print(f"{type(e).__name__}: {e}", file=sys.stderr)
            return 1
        return 0

    print(f"Network observability agent  [{backend} backend, {MODEL}]"
          "\nAsk a question, or 'quit' to exit.")
    while True:
        try:
            q = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if q.lower() in {"quit", "exit", "q"}:
            return 0
        if not q:
            continue
        try:
            print("\n" + answer(q))
        except Exception as e:
            print(f"{type(e).__name__}: {e}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
