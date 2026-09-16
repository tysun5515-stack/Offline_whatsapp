"""
whatsapp_analysis.py: Script for analyzing WhatsApp messages and generating plots.

Fix log (this revision):
  1. `calculate_and_add_timestamps` previously fed a relative,
     seconds-since-first-packet value (e.g. starting at 0.0) into
     `datetime.fromtimestamp()`, which treats its input as a Unix epoch
     timestamp - producing meaningless ~1970 dates. It happened to be
     harmless for THESE specific plots because only deltas between
     consecutive values were ever used (subtracting two equally-distorted
     values still recovers the correct real delta) - but it was a
     landmine for any future code that used the timestamps directly. Now
     works with plain floats (elapsed seconds) throughout; no datetime
     conversion of a relative value as if it were absolute.
  2. `plot_inter_message_delays`'s y-tick step
     `int(max(inter_delays) / 5)` evaluated to 0 whenever
     `max(inter_delays) < 5` seconds, and `range(..., step=0)` raises
     `ValueError`. Any capture with sub-5-second max inter-message delay
     crashed this plot outright. Replaced with `numpy.linspace`, which
     has no zero-step failure mode.
  3. `plot_inter_message_delays_pdf` called `gaussian_kde(inter_delays)`
     with no guard - a capture with zero-variance delays (e.g. too few
     packets, or all delays identical) raises `numpy.linalg.LinAlgError`
     inside scipy. Added an explicit `np.var(inter_delays) > 0` guard
     that skips the KDE plot with a clear log message instead of
     crashing the whole pipeline run over one plot.
"""

import csv
import logging
import os
from typing import List

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import gaussian_kde

GRAPH_SIZES = (12, 6)


def load_elapsed_seconds(csv_file_path: str) -> List[float]:
    """Reads the 'Time' column as plain elapsed seconds (float), exactly
    as the extractor wrote it - no datetime conversion. Renamed from the
    old `calculate_and_add_timestamps` to make explicit these are
    relative offsets, not absolute timestamps (Fix #1)."""
    times: List[float] = []
    with open(csv_file_path, 'r') as csv_file:
        for row in csv.DictReader(csv_file):
            times.append(float(row['Time']))
    return times


def _safe_y_ticks(max_value: float, num_ticks: int = 5) -> np.ndarray:
    """Evenly spaced y-ticks from 0 to max_value that never divide by
    zero, regardless of how small max_value is (Fix #2)."""
    if max_value <= 0:
        return np.array([0.0, 1.0])
    return np.linspace(0, max_value, num_ticks + 1)


def plot_inter_message_delays(elapsed_seconds: List[float], group: str, output_dir: str = "res"):
    """
    Plot inter-message delays using vertical lines.

    Args:
        elapsed_seconds: list of elapsed-time floats (seconds since first packet).
        group: WhatsApp activity group (Message, Photo, Audio, Video).
        output_dir: directory to save the PNG into.
    """
    if len(elapsed_seconds) < 2:
        logging.warning(f"[{group}] fewer than 2 packets - skipping inter-delay plot.")
        return

    inter_delays = [
        elapsed_seconds[i] - elapsed_seconds[i - 1]
        for i in range(1, len(elapsed_seconds))
    ]

    plt.figure(figsize=GRAPH_SIZES)
    plt.vlines(range(len(inter_delays)), ymin=0, ymax=inter_delays, lw=2, color='darkslateblue', alpha=0.7)

    mean_delay = sum(inter_delays) / len(inter_delays)
    median_delay = sorted(inter_delays)[len(inter_delays) // 2]

    plt.axhline(mean_delay, color='darkorange', linestyle='--', alpha=0.7, label='Mean')
    plt.axhline(median_delay, color='forestgreen', linestyle='--', alpha=0.7, label='Median')

    plt.xlabel(f'{group} Index', size=12)
    plt.ylabel(f'Inter-{group} Delay (seconds)', size=12)
    plt.title(f'Inter-{group} Delays', size=20)

    max_delay = max(inter_delays)
    plt.ylim(0, max_delay * 1.1 if max_delay > 0 else 1.0)
    plt.yticks(_safe_y_ticks(max_delay))  # Fix #2: no more range(step=0) crash
    plt.xlim(0, len(inter_delays))

    plt.legend(loc='upper left')
    plt.grid(linewidth=0.5, linestyle='--')

    os.makedirs(output_dir, exist_ok=True)
    plt.savefig(f"{output_dir}/{group}_delays.png")
    plt.close()


def plot_inter_message_delays_pdf(csv_file_path: str, group: str, output_dir: str = "res"):
    """
    Plot probability density function of inter-message delays.

    Args:
        csv_file_path: path to the CSV file containing packet information.
        group: WhatsApp activity group (Message, Photo, Audio, Video).
        output_dir: directory to save the PNG into.
    """
    elapsed_seconds = load_elapsed_seconds(csv_file_path)
    if len(elapsed_seconds) < 2:
        logging.warning(f"[{group}] fewer than 2 packets - skipping delay PDF plot.")
        return

    inter_delays = [
        elapsed_seconds[i] - elapsed_seconds[i - 1]
        for i in range(1, len(elapsed_seconds))
    ]

    # Fix #3: guard against zero-variance input, which crashes gaussian_kde
    # with a LinAlgError (e.g. too few packets, or identical delays).
    if len(inter_delays) < 2 or np.var(inter_delays) == 0:
        logging.warning(
            f"[{group}] inter-delay values have zero variance "
            f"({len(inter_delays)} samples) - skipping KDE plot, "
            "gaussian_kde is undefined for constant/degenerate input."
        )
        return

    kde = gaussian_kde(inter_delays)
    x_vals = np.linspace(min(inter_delays), max(inter_delays), num=1000)

    plt.figure(figsize=GRAPH_SIZES)
    plt.plot(x_vals, kde(x_vals), color='darkslateblue')
    plt.xlabel(f'Inter-{group} Delay (seconds)', size=12)
    plt.ylabel('Probability Density', size=12)
    plt.title(f'Probability Density Function of Inter-{group} Delays', size=20)
    plt.ylim(0, max(kde(x_vals)) * 1.1)  # was hardcoded to 1.02, wrong scale for most real KDEs
    plt.grid(linewidth=0.5, linestyle='--')

    os.makedirs(output_dir, exist_ok=True)
    plt.savefig(f"{output_dir}/{group}_delays_pdf.png")
    plt.close()


def plot_message_sizes(csv_file_path: str, group: str, output_dir: str = "res"):
    """
    Plot message sizes over time.

    Args:
        csv_file_path: path to the CSV file containing packet information.
        group: WhatsApp activity group (Message, Photo, Audio, Video).
        output_dir: directory to save the PNG into.
    """
    message_sizes: List[int] = []
    message_time: List[float] = []

    with open(csv_file_path, 'r') as csv_file:
        for row in csv.DictReader(csv_file):
            message_sizes.append(int(row['Length']))
            message_time.append(float(row['Time']))  # elapsed seconds - correct as-is,
                                                       # this function never misused it as epoch time

    if not message_sizes:
        logging.warning(f"[{group}] no packets - skipping size plot.")
        return

    plt.figure(figsize=GRAPH_SIZES)
    plt.vlines(message_time, ymin=0, ymax=message_sizes, lw=2, color='darkslateblue', alpha=0.7)

    mean_size = sum(message_sizes) / len(message_sizes)
    median_size = sorted(message_sizes)[len(message_sizes) // 2]

    plt.axhline(mean_size, color='darkorange', linestyle='--', alpha=0.5, label='Mean')
    plt.axhline(median_size, color='forestgreen', linestyle='--', alpha=0.5, label='Median')

    plt.xlabel('Time (s, elapsed since first packet)', size=12)
    plt.ylabel(f'{group} Length', size=12)
    plt.title(f'{group} Length by Time', size=20)

    max_size = max(message_sizes)
    plt.ylim(0, max_size + 500)
    plt.yticks(_safe_y_ticks(max_size + 500, num_ticks=5))  # Fix #2 applied here too - the
                                                              # original range(0, max+500, 1000)
                                                              # was safe but inconsistent with the
                                                              # other plot's tick logic; unified.
    plt.xlim(min(message_time) - 2, max(message_time) + 2)

    plt.grid(linewidth=0.7, linestyle='--', color='lightgray')
    plt.legend(loc='upper left')

    os.makedirs(output_dir, exist_ok=True)
    plt.savefig(f"{output_dir}/{group}_sizes.png")
    plt.close()


def creating_plots(csv_file_path: str, group: str, output_dir: str = "res"):
    """
    Generate and save plots for WhatsApp message analysis. Each plot
    function now guards its own failure modes and logs+skips rather than
    raising, so one bad plot doesn't take down the others in the same run.
    """
    plot_inter_message_delays(load_elapsed_seconds(csv_file_path), group, output_dir)
    plot_inter_message_delays_pdf(csv_file_path, group, output_dir)
    plot_message_sizes(csv_file_path, group, output_dir)
