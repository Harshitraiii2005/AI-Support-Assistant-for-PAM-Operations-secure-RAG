"""Streamlit chat UI. Talks to the API only; holds no model, index or audit access itself.

Run: streamlit run src/pam_copilot/ui.py
"""

from __future__ import annotations

import html
import os
import random
import re
from typing import Any

import httpx
import streamlit as st

from pam_copilot.loggen import generate

API_URL = os.environ.get("API_URL", "http://localhost:8000")
_PLACEHOLDER = re.compile(r"\[(?:[A-Z]+_)+\d+\]")
_REASONS = {
    "prompt_injection": "Blocked: possible prompt injection",
    "no_relevant_context": "Refused: no relevant runbook for your role",
    "INSUFFICIENT_CONTEXT": "Refused: the runbooks don't answer this",
    "uncited_answer": "Refused: answer could not be grounded in a citation",
    "output_blocked": "Blocked by output filter",
    "no_matching_runbook": "No matching runbook",
    "admin_only_runbook": "Admin-only runbook: escalate",
}

st.set_page_config(page_title="PAM Copilot", page_icon="🔐", layout="wide")
st.markdown("<style>mark{background:#f6c344;color:#000;border-radius:3px;padding:0 2px}"
            "pre.box{white-space:pre-wrap;font-size:0.8rem;padding:0.6rem;border-radius:6px;"
            "border:1px solid rgba(128,128,128,.35)}</style>", unsafe_allow_html=True)


def call(method: str, path: str, **kwargs: Any) -> dict[str, Any] | None:
    token = st.session_state.get("token", "")
    try:
        r = httpx.request(method, f"{API_URL}{path}", timeout=300,
                          headers={"Authorization": f"Bearer {token}"}, **kwargs)
    except httpx.HTTPError as exc:
        st.error(f"API unreachable at {API_URL}: {exc}")
        return None
    if r.status_code != 200:
        detail = r.json().get("detail", r.text) if r.headers.get(
            "content-type", "").startswith("application/json") else r.text
        st.error(f"{r.status_code}: {detail}")
        return None
    result: dict[str, Any] = r.json()
    return result


def _box(inner: str) -> str:
    # explicit <br>: Streamlit's markdown pass collapses newlines inside raw HTML
    return f'<pre class="box">{inner.replace(chr(10), "<br>")}</pre>'


def highlight_original(text: str, findings: list[dict[str, Any]]) -> str:
    out, cursor = [], 0
    for f in sorted(findings, key=lambda f: f["start"]):
        out.append(html.escape(text[cursor:f["start"]]))
        out.append(f'<mark title="{f["kind"]}">{html.escape(text[f["start"]:f["end"]])}</mark>')
        cursor = f["end"]
    out.append(html.escape(text[cursor:]))
    return _box("".join(out))


def highlight_redacted(text: str) -> str:
    return _box(_PLACEHOLDER.sub(lambda m: f"<mark>{m.group()}</mark>", html.escape(text)))


def redaction_view(original: str, result: dict[str, Any]) -> None:
    findings = result["redactions"]
    kinds = sorted({f["kind"] for f in findings})
    with st.expander(f"Redaction: {len(findings)} value(s) masked before the LLM "
                     f"{'(' + ', '.join(kinds) + ')' if kinds else ''}", expanded=bool(findings)):
        before, after = st.columns(2)
        before.caption("Before (stays on this side)")
        before.markdown(highlight_original(original, findings), unsafe_allow_html=True)
        after.caption("After (the only text the LLM sees)")
        after.markdown(highlight_redacted(result["redacted_input"]), unsafe_allow_html=True)
    if result["injection_flags"]:
        st.warning("Prompt-injection heuristics matched: " + ", ".join(result["injection_flags"]))


def sources_view(citations: list[dict[str, Any]]) -> None:
    if citations:
        with st.expander(f"Sources ({len(citations)})"):
            for c in citations:
                where = f"p. {c['page']}" if c["page"] else c["section"]
                st.markdown(f"**[{c['n']}]** `{c['runbook_id'] or c['source']}` {c['title']} "
                            f"› {where} · updated {c['last_updated']}")


def render_answer(question: str, res: dict[str, Any]) -> None:
    if res["refused"]:
        st.warning(f"**{_REASONS.get(res['reason'], res['reason'])}**\n\n{res['answer']}")
    else:
        st.markdown(res["answer"])
    sources_view(res["citations"])
    redaction_view(question, res)


with st.sidebar:
    st.title("🔐 PAM Copilot")
    st.caption("Local LLM · approved runbooks only · secrets never reach the model")
    st.text_input("Access token", type="password", key="token",
                  help="OPERATOR_TOKEN or ADMIN_TOKEN from your .env")
    me = call("GET", "/whoami") if st.session_state.get("token") else None
    role = me["role"] if me else None
    if me:
        st.success(f"Signed in as **{me['user']}** ({me['role']})")
    st.caption(f"API: {API_URL}")
    st.caption("Demo data is fictional. `SIM-` error codes are simulated.")

if not role:
    st.info("Enter an access token in the sidebar to start.")
    st.stop()

ask_tab, diag_tab, audit_tab = st.tabs(["💬 Ask", "🩺 Diagnose log", "📜 Audit log"])

with ask_tab:
    # inside a tab chat_input renders inline, so draw it first to keep it on top
    question = st.chat_input("Ask about CPM, PSM, PVWA, Safes, audits...")
    history: list[tuple[str, dict[str, Any]]] = st.session_state.setdefault("history", [])
    for q, res in history:
        with st.chat_message("user"):
            st.markdown(q)
        with st.chat_message("assistant"):
            render_answer(q, res)
    if question:
        with st.chat_message("user"):
            st.markdown(question)
        with st.chat_message("assistant"), st.spinner("Retrieving runbooks and generating..."):
            reply = call("POST", "/ask", json={"question": question})
            if reply:
                render_answer(question, reply)
                history.append((question, reply))

with diag_tab:
    st.caption("Paste a CPM / PSM / PVWA / Vault log. It is redacted before anything else "
               "touches it.")
    if st.button("Load a simulated log with fake secrets"):
        st.session_state["log"] = generate(1, seed=random.randrange(10**6),
                                           with_secrets=True)[0].log
    log = st.text_area("Log", key="log", height=220)
    if st.button("Diagnose", type="primary", disabled=not log.strip()):
        with st.spinner("Classifying and building a fix from the runbook..."):
            d = call("POST", "/diagnose", json={"log": log})
        if d:
            a, b, c = st.columns(3)
            a.metric("Error code", d["error_code"] or "none found")
            b.metric("Runbook", d["runbook_id"] or "none")
            c.metric("Confidence", d["confidence"], help=d["basis"])
            st.caption(f"Basis: {d['basis']}")
            if d["removed_lines"]:
                st.error(f"Removed line(s) {d['removed_lines']}: possible prompt injection.")
            if d["confidence"] == "low":
                st.info("Low confidence: no known error code in the log. Confirm the matched "
                        "runbook fits before acting.")
            if d["escalate"]:
                st.warning(f"**Escalate.** {_REASONS.get(d['reason'] or '', '')}")
            st.markdown(d["answer"])
            sources_view(d["citations"])
            redaction_view(log, d)

with audit_tab:
    if role != "admin":
        st.info("The audit log is visible to admins only.")
    elif st.button("Load latest entries"):
        data = call("GET", "/audit", params={"limit": 100})
        if data:
            if data["chain_ok"]:
                st.success(f"Hash chain intact ({data['checked']} entries checked)")
            else:
                st.error(f"Hash chain BROKEN at line {data['checked']}: log was tampered with")
            st.dataframe([{
                "time (UTC)": e["ts"][:19].replace("T", " "), "role": e["role"],
                "kind": e["kind"], "refused": e["refused"], "reason": e["reason"] or "",
                "masked": ", ".join(f"{k}:{v}" for k, v in e["redactions"].items()),
                "injection": ", ".join(e["injection_flags"]), "ms": e["latency_ms"],
                "input (redacted)": e["input"][:80],
            } for e in reversed(data["entries"])], use_container_width=True, hide_index=True,
                column_config={c: st.column_config.TextColumn(width="medium")
                               for c in ("reason", "masked", "injection")})
