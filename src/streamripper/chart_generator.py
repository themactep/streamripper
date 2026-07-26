import pandas as pd
import matplotlib.pyplot as plt
import argparse
import os


def generate_combined_chart(output_dir, data, timestamp_prefix):
    """Generates a combined chart showing frame sizes and separate audio/video time drifts."""
    fig, ax1 = plt.subplots(figsize=(16, 9))

    video_data = data[data['Type'].isin(['I', 'P', 'B'])]
    audio_data = data[data['Type'] == 'A']
    subtitle_data = data[data['Type'] == 'S']
    sei_data = data[data['Has SEI'] == True]

    # Frame Size Plot (Primary Y-axis)
    ax1.set_xlabel('Packet Number')
    ax1.set_ylabel('Packet Size (KB)', color='blue')

    if not video_data.empty:
        ax1.plot(video_data['Packet'], video_data['Packet Size (bytes)'] / 1024,
                color='blue', alpha=0.6, label='Video Frame Size', linestyle='-', marker='None')

    if not audio_data.empty:
        ax1.plot(audio_data['Packet'], audio_data['Packet Size (bytes)'] / 1024,
                color='lightblue', alpha=0.4, label='Audio Packet Size', linestyle='-', marker='None')

    if not subtitle_data.empty:
        ax1.scatter(subtitle_data['Packet'], subtitle_data['Packet Size (bytes)'] / 1024,
                   color='purple', alpha=0.7, label='Subtitle Packets', s=20, marker='s')

    ax1.tick_params(axis='y', labelcolor='blue')
    ax1.grid(True)

    # Time Drift Plot (Secondary Y-axis)
    ax2 = ax1.twinx()
    ax2.set_ylabel('Time Drift (ms)', color='red')

    if not video_data.empty:
        ax2.plot(video_data['Packet'], video_data['Drift (ms)'],
                color='red', alpha=0.8, label='Video Time Drift', linestyle='-', linewidth=2)

    if not audio_data.empty:
        ax2.plot(audio_data['Packet'], audio_data['Drift (ms)'],
                color='orange', alpha=0.8, label='Audio Time Drift', linestyle='--', linewidth=2)

    ax2.tick_params(axis='y', labelcolor='red')

    all_drifts = data['Drift (ms)'].dropna()
    if not all_drifts.empty:
        min_drift, max_drift = all_drifts.min(), all_drifts.max()
        drift_range = max_drift - min_drift
        ax2.set_ylim(min_drift - drift_range * 0.1, max_drift + drift_range * 0.1)

    if not sei_data.empty:
        for _, row in sei_data.iterrows():
            ax1.axvline(x=row['Packet'], color='green', alpha=0.3, linestyle=':', linewidth=1)

    fig.suptitle(f'Stream Analysis - Frame Sizes & Time Drifts', fontsize=16)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc='upper right')

    fig.tight_layout(rect=[0, 0, 1, 0.95])

    chart_path = os.path.join(output_dir, "chart_combined.png")
    plt.savefig(chart_path, dpi=300, bbox_inches='tight')
    print(f"Combined chart saved to {chart_path}")

def generate_comprehensive_chart(output_dir, data, timestamp_prefix):
    """Generates a comprehensive chart showing all packets with separate audio/video drift lines."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 12), sharex=True)

    video_data = data[data['Type'].isin(['I', 'P', 'B'])]
    audio_data = data[data['Type'] == 'A']
    subtitle_data = data[data['Type'] == 'S']
    sei_data = data[data['Has SEI'] == True]

    # Top subplot: Packet Sizes
    ax1.set_ylabel('Packet Size (KB)', color='black')

    if not video_data.empty:
        i_frames = video_data[video_data['Type'] == 'I']
        p_frames = video_data[video_data['Type'] == 'P']
        b_frames = video_data[video_data['Type'] == 'B']

        if not i_frames.empty:
            ax1.scatter(i_frames['Packet'], i_frames['Packet Size (bytes)'] / 1024,
                       color='green', alpha=0.8, label='I-frames', s=30, marker='o')
        if not p_frames.empty:
            ax1.scatter(p_frames['Packet'], p_frames['Packet Size (bytes)'] / 1024,
                       color='blue', alpha=0.6, label='P-frames', s=20, marker='.')
        if not b_frames.empty:
            ax1.scatter(b_frames['Packet'], b_frames['Packet Size (bytes)'] / 1024,
                       color='purple', alpha=0.6, label='B-frames', s=20, marker='.')

    if not audio_data.empty:
        ax1.scatter(audio_data['Packet'], audio_data['Packet Size (bytes)'] / 1024,
                   color='orange', alpha=0.5, label='Audio packets', s=10, marker='x')

    if not subtitle_data.empty:
        ax1.scatter(subtitle_data['Packet'], subtitle_data['Packet Size (bytes)'] / 1024,
                   color='purple', alpha=0.7, label='Subtitle packets', s=25, marker='s')

    if not sei_data.empty:
        for _, row in sei_data.iterrows():
            ax1.axvline(x=row['Packet'], color='green', alpha=0.25, linestyle=':', linewidth=1)

    ax1.grid(True, alpha=0.3)
    ax1.legend(loc='upper right')
    ax1.set_title(f'Stream Analysis - Packet Sizes and Time Drifts\nRun at: {timestamp_prefix}', fontsize=14)

    # Bottom subplot: Time Drifts
    ax2.set_xlabel('Packet Number')
    ax2.set_ylabel('Time Drift (ms)', color='black')

    if not video_data.empty:
        ax2.plot(video_data['Packet'], video_data['Drift (ms)'],
                color='red', alpha=0.8, label='Video Time Drift', linestyle='-', linewidth=2)

    if not audio_data.empty:
        ax2.plot(audio_data['Packet'], audio_data['Drift (ms)'],
                color='orange', alpha=0.8, label='Audio Time Drift', linestyle='--', linewidth=2)

    if not subtitle_data.empty:
        ax2.scatter(subtitle_data['Packet'], subtitle_data['Drift (ms)'],
                   color='purple', alpha=0.7, label='Subtitle Drift', s=20, marker='s')

    ax2.grid(True, alpha=0.3)
    ax2.legend(loc='upper right')

    all_drifts = data['Drift (ms)'].dropna()
    if not all_drifts.empty:
        min_drift, max_drift = all_drifts.min(), all_drifts.max()
        drift_range = max_drift - min_drift
        ax2.set_ylim(min_drift - drift_range * 0.1, max_drift + drift_range * 0.1)

    ax2.axhline(y=0, color='gray', linestyle=':', alpha=0.5, label='Zero drift')

    plt.tight_layout()

    chart_path = os.path.join(output_dir, "chart_comprehensive.png")
    plt.savefig(chart_path, dpi=300, bbox_inches='tight')
    print(f"Comprehensive chart saved to {chart_path}")
    plt.close()

def generate_video_chart(output_dir, data, timestamp_prefix):
    """Generates a visual chart for the video stream analysis."""
    fig, ax1 = plt.subplots(figsize=(16, 9))

    # Frame Size and Type Plot
    ax1.set_xlabel('Frame Number')
    ax1.set_ylabel('Frame Size (KB)', color='blue')
    ax1.plot(data['Packet'], data['Packet Size (bytes)'] / 1024, color='blue', alpha=0.6, label='Frame Size', linestyle='-', marker='None')
    ax1.tick_params(axis='y', labelcolor='blue')
    ax1.grid(True)

    colors = {'I': 'green', 'P': 'blue', 'B': 'purple', 'UNKNOWN': 'gray'}
    # Time Drift Plot (Secondary Y-axis)
    ax2 = ax1.twinx()
    ax2.set_ylabel('Time Drift (ms)', color='red')
    ax2.plot(data['Packet'], data['Drift (ms)'], color='red', alpha=0.7, label='Time Drift', linestyle='-', marker='None')
    ax2.tick_params(axis='y', labelcolor='red')
    min_drift, max_drift = min(data['Drift (ms)']), max(data['Drift (ms)'])
    ax2.set_ylim(min_drift - 2000, max_drift + 100)

    fig.suptitle(f'Video Stream Analysis\nRun at: {timestamp_prefix}', fontsize=16)
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines + lines2, labels + labels2, loc='upper right')

    fig.tight_layout(rect=[0, 0, 1, 0.95])

    chart_path = os.path.join(output_dir, "chart_video.png")
    plt.savefig(chart_path)
    print(f"Video chart saved to {chart_path}")

def generate_audio_chart(output_dir, data, timestamp_prefix):
    """Generates a visual chart for the audio stream analysis."""
    fig, ax1 = plt.subplots(figsize=(16, 9))

    # Packet Size Plot
    ax1.set_xlabel('Packet Number')
    ax1.set_ylabel('Packet Size (bytes)', color='blue')
    ax1.plot(data['Packet'], data['Packet Size (bytes)'], color='blue', alpha=0.6, label='Packet Size', linestyle='-', marker='None')
    ax1.tick_params(axis='y', labelcolor='blue')
    ax1.grid(True)

    # Time Drift Plot (Secondary Y-axis)
    ax2 = ax1.twinx()
    ax2.set_ylabel('Time Drift (ms)', color='red')
    ax2.plot(data['Packet'], data['Drift (ms)'], color='red', alpha=0.7, label='Time Drift', linestyle='-', marker='None')
    ax2.tick_params(axis='y', labelcolor='red')

    fig.suptitle(f'Audio Stream Analysis\nRun at: {timestamp_prefix}', fontsize=16)
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines + lines2, labels + labels2, loc='upper right')
    
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    
    chart_path = os.path.join(output_dir, "chart_audio.png")
    plt.savefig(chart_path)
    print(f"Audio chart saved to {chart_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate charts from stream analysis CSV files.")
    parser.add_argument("directory", help="Directory containing the flow.csv and audio_flow.csv files.")
    
    args = parser.parse_args()

    # Find the latest timestamp prefix
    timestamps = set()
    for f in os.listdir(args.directory):
        if f.endswith("_flow.csv"):
            timestamps.add(f.replace("_flow.csv", ""))
    
    if not timestamps:
        print("No flow.csv files found in the directory.")
        exit(1)

    latest_timestamp = max(timestamps)

    flow_csv_path = os.path.join(args.directory, f"{latest_timestamp}_flow.csv")

    if os.path.exists(flow_csv_path):
        all_data = pd.read_csv(flow_csv_path)
        video_data = all_data[all_data['Type'].isin(['I', 'P', 'B'])]
        audio_data = all_data[all_data['Type'] == 'A']

        if not video_data.empty:
            generate_video_chart(args.directory, video_data, latest_timestamp)
        if not audio_data.empty:
            generate_audio_chart(args.directory, audio_data, latest_timestamp)
    else:
        print(f"Flow data file not found: {flow_csv_path}")