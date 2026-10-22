"""Render paper figures (vector PDF) from the results JSON files."""
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({
    # NeurIPS does not permit Type 3 fonts in submitted PDFs. Embed TrueType
    # outlines in the vector figures instead of Matplotlib's Type 3 default.
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
    "font.family": "serif",
    "font.serif": ["DejaVu Serif"],
    "mathtext.fontset": "dejavuserif",
    "font.size": 9,
    "axes.titlesize": 9,
    "axes.labelsize": 9,
    "legend.fontsize": 7.6,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "lines.linewidth": 1.6,
    "figure.dpi": 200,
})

C_FA = "#c1272d"   # false-approve (security)  -> red
C_FR = "#1f5c99"   # false-reject (availability) -> blue
C_BASE = "#8a8a8a"

committee = json.load(open("results/committee.json"))
bench = json.load(open("results/bls_bench.json"))["rows"]

# ----------------------------------------------------------------------
# Figure 1: committee accuracy  (two panels)
# ----------------------------------------------------------------------
fig, (axL, axR) = plt.subplots(1, 2, figsize=(5.6, 2.4))

# Panel A: sweep threshold t
pa = committee["panel_a"]
ts = [r["t"] for r in pa["sweep_t"]]
fa = [r["FA"]["rate"] for r in pa["sweep_t"]]
fr = [r["FR"]["rate"] for r in pa["sweep_t"]]
axL.plot(ts, fa, "o-", color=C_FA, label="False approval")
axL.plot(ts, fr, "s-", color=C_FR, label="False rejection")
axL.axhline(committee["params"]["P_B"], ls=":", color=C_FA, lw=1.1)
axL.axhline(1 - committee["params"]["P_G"], ls=":", color=C_FR, lw=1.1)
axL.text(1.05, committee["params"]["P_B"] * 1.15, "single-reviewer FA", color=C_FA,
         fontsize=6.4)
axL.text(1.05, (1 - committee["params"]["P_G"]) * 0.42, "single-reviewer FR",
         color=C_FR, fontsize=6.4)
axL.axvline(4, color=C_BASE, ls="--", lw=0.9)
axL.text(4.08, 0.85, "majority", rotation=90, color=C_BASE, fontsize=6.4, va="top")
axL.set_yscale("log")
axL.set_xlabel(r"approval threshold $t$  (of $n{=}7$)")
axL.set_ylabel("error rate (log)")
axL.set_title(r"(a) Effect of approval threshold")
axL.set_xticks(ts)
axL.legend(loc="lower center", frameon=True, facecolor="white",
           edgecolor="none", framealpha=1, handlelength=1.4)

# Panel B: sweep correlation rho at majority threshold
pb = committee["panel_b"]
rho = [r["latent_rho"] for r in pb["sweep_latent_rho"]]
fab = [r["FA"]["rate"] for r in pb["sweep_latent_rho"]]
frb = [r["FR"]["rate"] for r in pb["sweep_latent_rho"]]
axR.plot(rho, fab, "-", color=C_FA, label="False approval")
axR.plot(rho, frb, "-", color=C_FR, label="False rejection")
axR.axhline(pb["single_reviewer"]["FA"], ls=":", color=C_FA, lw=1.1)
axR.axhline(pb["single_reviewer"]["FR"], ls=":", color=C_FR, lw=1.1)
axR.text(0.02, pb["single_reviewer"]["FA"] * 0.97, "single-reviewer FA", color=C_FA,
         fontsize=6.4, va="top")
axR.set_xlabel(r"latent score correlation $\rho$")
axR.set_ylabel("error rate")
axR.set_title(r"(b) Effect of reviewer dependence")
axR.set_xlim(0, 1)
axR.legend(loc="upper left", frameon=False, handlelength=1.4,
           bbox_to_anchor=(0.0, 0.92))

fig.tight_layout(pad=0.4)
fig.subplots_adjust(wspace=0.33)
fig.savefig("figures/fig_committee.pdf", bbox_inches="tight")
print("saved figures/fig_committee.pdf")

# ----------------------------------------------------------------------
# Figure 2: threshold-BLS microbenchmark scaling
# ----------------------------------------------------------------------
fig2, ax = plt.subplots(figsize=(3.35, 2.5))
tt = [r["t"] for r in bench]
part = [r["partial_sign_ms"]["mean"] for r in bench]
part_ver = [r["partial_verify_ms"]["mean"] for r in bench]
agg = [r["aggregate_ms"]["mean"] for r in bench]
ver = [r["final_verify_ms"]["mean"] for r in bench]
ax.plot(tt, ver, "o-", color="#4b0082", label="verify (2 pairings, $O(1)$)")
ax.plot(tt, agg, "s-", color="#1f5c99", label=r"aggregate ($\propto t$)")
ax.plot(tt, part, "^-", color="#2e8b57", label="partial-sign / node (1 round)")
ax.plot(tt, part_ver, "d-", color="#9a6700", label="validate one partial")
ax.set_yscale("log")
ax.set_xlabel(r"threshold $t$ (number of signing reviewers)")
ax.set_ylabel("time per op (ms, log)")
ax.set_title("Threshold-BLS signing cost")
ax.legend(loc="center left", frameon=False, handlelength=1.4, fontsize=7.0)
ax.grid(True, which="major", axis="y", ls=":", lw=0.5, alpha=0.6)
fig2.tight_layout(pad=0.3)
fig2.savefig("figures/fig_crypto.pdf", bbox_inches="tight")
print("saved figures/fig_crypto.pdf")
