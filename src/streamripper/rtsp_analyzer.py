import av
import argparse
import time
import os
import re
import pandas as pd
from datetime import datetime
from collections import Counter
from dataclasses import dataclass

@dataclass
class PacketInfo:
    __slots__ = ['type', 'wall_clock', 'stream_offset', 'packet_number', 'timestamp', 'size', 'drift', 'sei_metadata', 'subtitle_data']
    type: str
    wall_clock: float
    stream_offset: int
    packet_number: int
    timestamp: float
    size: int
    drift: float
    sei_metadata: str
    subtitle_data: str

@dataclass
class CorruptedPacketInfo:
    __slots__ = ['packet_index', 'stream_offset', 'timestamp', 'size', 'error', 'error_type', 'frame_type', 'packet_data']
    packet_index: int
    stream_offset: int
    timestamp: any
    size: int
    error: str
    error_type: str
    frame_type: str
    packet_data: bytes



def _get_h264_frame_type(packet_data):
    """
    Detect H.264 frame type from packet data.

    H.264 NAL unit types:
    - 1: Coded slice of a non-IDR picture (P-frame)
    - 2: Coded slice data partition A
    - 3: Coded slice data partition B
    - 4: Coded slice data partition C
    - 5: Coded slice of an IDR picture (I-frame)
    - 6: Supplemental enhancement information (SEI)
    - 7: Sequence parameter set (SPS)
    - 8: Picture parameter set (PPS)
    - 9: Access unit delimiter
    - 10: End of sequence
    - 11: End of stream

    Args:
        packet_data (bytes): Raw H.264 packet data

    Returns:
        tuple: (frame_type_str, nal_type_int, start_offset)
    """
    if len(packet_data) < 4:
        return ("Unknown (too small)", None, -1)

    try:
        # Look for start code (00 00 00 01 or 00 00 01)
        start_idx = -1
        if packet_data[:4] == b'\x00\x00\x00\x01':
            start_idx = 4
        elif packet_data[:3] == b'\x00\x00\x01':
            start_idx = 3
        else:
            # Search for start code
            for i in range(len(packet_data) - 3):
                if packet_data[i:i+4] == b'\x00\x00\x00\x01':
                    start_idx = i + 4
                    break
                elif packet_data[i:i+3] == b'\x00\x00\x01':
                    start_idx = i + 3
                    break

        if start_idx == -1 or start_idx >= len(packet_data):
            return ("Unknown (no start code)", None, -1)

        # Extract NAL unit type (lower 5 bits of first byte after start code)
        nal_byte = packet_data[start_idx]
        nal_type = nal_byte & 0x1F

        frame_types = {
            1: "P-frame (non-IDR slice)",
            2: "Slice partition A",
            3: "Slice partition B",
            4: "Slice partition C",
            5: "I-frame (IDR slice)",
            6: "SEI (Supplemental Enhancement Info)",
            7: "SPS (Sequence Parameter Set)",
            8: "PPS (Picture Parameter Set)",
            9: "Access Unit Delimiter",
            10: "End of Sequence",
            11: "End of Stream",
        }

        frame_type_str = frame_types.get(nal_type, f"Unknown NAL type {nal_type}")
        return (frame_type_str, nal_type, start_idx - 4 if start_idx >= 4 else 0)
    except Exception as e:
        return (f"Error detecting frame type: {e}", None, -1)

def _scan_h264_sei_nal_units(packet_data):
    sei_nal_units = []
    i = 0
    while i < len(packet_data) - 3:
        if packet_data[i:i+4] == b'\x00\x00\x00\x01':
            start = i
            nal_start = i + 4
            i = nal_start
        elif packet_data[i:i+3] == b'\x00\x00\x01':
            start = i
            nal_start = i + 3
            i = nal_start
        else:
            i += 1
            continue

        if nal_start >= len(packet_data):
            break

        nal_type = packet_data[nal_start] & 0x1F
        if nal_type == 6:
            end = len(packet_data)
            for j in range(i, len(packet_data) - 3):
                if packet_data[j:j+4] == b'\x00\x00\x00\x01' or packet_data[j:j+3] == b'\x00\x00\x01':
                    end = j
                    break
            sei_nal_units.append((start, end))

    return sei_nal_units

def _save_hex_dump(hex_dump_dir, stream_offset, packet_data, frame_type_info=None):
    """
    Save packet data as hex dump and binary files for forensic analysis.

    Args:
        hex_dump_dir (str): Directory to save hex dumps
        stream_offset (int): Byte offset in the stream where this packet starts
        packet_data (bytes): Raw packet data
        frame_type_info (tuple): Optional (frame_type_str, nal_type, offset)
    """
    try:
        # Use hex offset as filename (padded to 8 hex digits)
        filename_base = f"{stream_offset:08x}"
        hex_filename = os.path.join(hex_dump_dir, f"{filename_base}.hex")
        bin_filename = os.path.join(hex_dump_dir, f"{filename_base}.bin")

        # Save binary file
        with open(bin_filename, 'wb') as f:
            f.write(packet_data)

        # Save hex dump file
        with open(hex_filename, 'w') as f:
            # Write header
            f.write(f"Stream Offset: 0x{stream_offset:08x} ({stream_offset} bytes)\n")
            f.write(f"Packet Size: {len(packet_data)} bytes\n")

            if frame_type_info is None:
                frame_type_info = _get_h264_frame_type(packet_data)

            frame_type_str, nal_type, start_offset = frame_type_info
            f.write(f"Frame Type: {frame_type_str}\n")
            if nal_type is not None:
                f.write(f"NAL Type: {nal_type}\n")
            if start_offset >= 0:
                f.write(f"Start Code Offset: {start_offset}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write("=" * 80 + "\n\n")

            # Write hex dump with ASCII representation
            for i in range(0, len(packet_data), 16):
                chunk = packet_data[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                f.write(f"{i:08x}  {hex_str:<48}  {ascii_str}\n")
    except Exception as e:
        print(f"Warning: Could not save hex dump for offset 0x{stream_offset:08x}: {e}")

def sanitize_url_for_filename(url):
    """
    Sanitizes a URL to be used as a safe directory name.

    Removes credentials and protocol, replaces non-alphanumeric characters with underscores.

    Args:
        url (str): The original URL

    Returns:
        str: Sanitized string safe for use as directory name

    Examples:
        rtsp://user:pass@192.168.1.100/ch0 -> 192_168_1_100_ch0
        rtsp://camera.example.com:554/stream -> camera_example_com_554_stream
    """
    # Remove credentials (everything between :// and @)
    url_no_creds = re.sub(r"://.*?@", "://", url)

    # Replace all non-alphanumeric characters with underscores
    sanitized = re.sub(r'[^a-zA-Z0-9]', '_', url_no_creds)

    # Remove multiple consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)

    # Remove leading/trailing underscores
    sanitized = sanitized.strip('_')

    # Ensure it's not empty
    if not sanitized:
        sanitized = "unknown_stream"

    return sanitized

def analyze_rtsp_stream(rtsp_url, duration, output_dir, debug_log, timestamp_prefix, save_stream=False, forensic_mode=False):
    """
    Analyzes an RTSP stream for a given duration and generates a report.

    Args:
        rtsp_url (str): The URL of the RTSP stream.
        duration (int): The duration in seconds to analyze the stream.
        output_dir (str): Base directory to save output files.
        debug_log (bool): Whether to enable per-frame debug logging.
        timestamp_prefix (str): Prefix for output files based on timestamp.
        save_stream (bool): Whether to save the unaltered raw stream to file.
        forensic_mode (bool): Whether to extract and analyze corrupted packets.

    Returns:
        tuple: (pandas.DataFrame with analysis data, str with output directory path)
               Returns (None, output_dir) if analysis failed.

    Note:
        Creates organized directory structure: output_dir/sanitized_url/YYYYMMDD_HHMMSS/
    """
    # Create organized output directory structure: output_dir/sanitized_url/timestamp/
    sanitized_url = sanitize_url_for_filename(rtsp_url)
    timestamp_dir = datetime.now().strftime('%Y%m%d_%H%M%S')
    stream_output_dir = os.path.join(output_dir, sanitized_url, timestamp_dir)
    os.makedirs(stream_output_dir, exist_ok=True)

    try:
        container = av.open(rtsp_url, timeout=10)
    except Exception as e:
        report = f"Error: Could not open RTSP stream at {rtsp_url}: {e}\n"
        print(report)
        with open(os.path.join(stream_output_dir, "report.txt"), "w") as f:
            f.write(report)
        return None, stream_output_dir

    video_stream = container.streams.video[0]
    audio_stream = None
    if container.streams.audio:
        audio_stream = container.streams.audio[0]
    subtitle_stream = None
    if container.streams.subtitles:
        subtitle_stream = container.streams.subtitles[0]




    # Set up raw stream saving (complete unaltered binary from camera)
    raw_stream_file = None
    raw_stream_filename = None
    if save_stream:
        raw_stream_filename = os.path.join(stream_output_dir, "stream.raw")
        try:
            raw_stream_file = open(raw_stream_filename, 'wb')
            print(f"Raw stream will be saved to: {raw_stream_filename}")
        except Exception as e:
            print(f"Warning: Could not create raw stream file: {e}")
            save_stream = False
            raw_stream_file = None

    # Also save video-only stream for reference
    video_stream_file = None
    video_stream_filename = None
    if save_stream:
        # Determine codec and file extension
        video_codec = video_stream.codec_context.name
        if video_codec == 'h264':
            video_stream_filename = os.path.join(stream_output_dir, "stream.h264")
        elif video_codec == 'hevc':
            video_stream_filename = os.path.join(stream_output_dir, "stream.h265")
        else:
            video_stream_filename = os.path.join(stream_output_dir, f"stream.{video_codec}")

        try:
            video_stream_file = open(video_stream_filename, 'wb')
            print(f"Video stream will be saved to: {video_stream_filename}")
        except Exception as e:
            print(f"Warning: Could not create video stream file: {e}")
            video_stream_file = None

    # Also save audio-only stream for reference
    audio_stream_file = None
    audio_stream_filename = None
    if save_stream and audio_stream:
        audio_codec = audio_stream.codec_context.name
        audio_stream_filename = os.path.join(stream_output_dir, f"stream.{audio_codec}")
        try:
            audio_stream_file = open(audio_stream_filename, 'wb')
            print(f"Audio stream will be saved to: {audio_stream_filename}")
        except Exception as e:
            print(f"Warning: Could not create audio stream file: {e}")
            audio_stream_file = None

    # Also save subtitle stream for reference
    subtitle_stream_file = None
    subtitle_stream_filename = None
    if save_stream and subtitle_stream:
        subtitle_stream_filename = os.path.join(stream_output_dir, "stream.sub")
        try:
            subtitle_stream_file = open(subtitle_stream_filename, 'wb')
            print(f"Subtitle stream will be saved to: {subtitle_stream_filename}")
        except Exception as e:
            print(f"Warning: Could not create subtitle stream file: {e}")
            subtitle_stream_file = None

    # Also save SEI NAL units as a separate stream
    sei_stream_file = None
    sei_stream_filename = None
    if save_stream:
        sei_stream_filename = os.path.join(stream_output_dir, "stream.sei")
        try:
            sei_stream_file = open(sei_stream_filename, 'wb')
            print(f"SEI data will be saved to: {sei_stream_filename}")
        except Exception as e:
            print(f"Warning: Could not create SEI stream file: {e}")
            sei_stream_file = None



    packets = []
    corrupted_packets = []  # Track corrupted packets for forensic analysis
    start_time = time.time()

    report_lines = []
    report_lines.append(f"RTSP Stream Forensic Analysis Report")
    report_lines.append(f"Stream URL: {rtsp_url}")
    report_lines.append(f"Analysis started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("-" * 30)
    report_lines.append(f"Video Codec: {video_stream.codec_context.name}")
    if audio_stream:
        report_lines.append(f"Audio Codec: {audio_stream.codec_context.name}")
    if forensic_mode:
        report_lines.append("Forensic Mode: ENABLED - Corrupted packets will be extracted")
    report_lines.append("-" * 30)

    log_file = None
    if debug_log:
        log_path = os.path.join(stream_output_dir, "flow.csv")
        log_file = open(log_path, "w")
        log_file.write("Wall Clock Time (ms),Stream Offset (hex),Stream Offset (dec),Packet Number,Type,Packet Size (bytes),Timestamp (ms),Drift (ms)\n")

    first_frame_wall_time = None
    first_pts = None
    first_audio_wall_time = None
    first_audio_pts = None
    first_subtitle_wall_time = None
    first_subtitle_pts = None

    streams_to_demux = [video_stream]
    if audio_stream:
        streams_to_demux.append(audio_stream)
    if subtitle_stream:
        streams_to_demux.append(subtitle_stream)

    # Track stream offsets
    # For video: use actual offset from PyAV (when we save to file)
    # For audio: calculate based on last known video offset + accumulated audio sizes
    last_video_offset = 0
    audio_offset_accumulator = 0
    subtitle_offset_accumulator = 0

    for packet in container.demux(streams_to_demux):
        if (time.time() - start_time) > duration:
            break

        # Save to raw stream (everything, unaltered)
        if save_stream and raw_stream_file:
            try:
                packet_bytes = bytes(packet)
                raw_stream_file.write(packet_bytes)
            except Exception as e:
                pass

        if packet.stream.type == 'video':
            # Video packet: use actual file offset
            packet_stream_offset = last_video_offset + audio_offset_accumulator

            # Save video packet to video-only stream
            if save_stream and video_stream_file:
                try:
                    packet_bytes = bytes(packet)
                    video_stream_file.write(packet_bytes)
                except Exception as e:
                    # Continue analysis even if saving fails
                    pass

            # Update last video offset for next audio packets
            last_video_offset = packet_stream_offset + packet.size
            audio_offset_accumulator = 0
            subtitle_offset_accumulator = 0
        elif packet.stream.type == 'audio':
            packet_stream_offset = last_video_offset + audio_offset_accumulator

            if save_stream and audio_stream_file:
                try:
                    packet_bytes = bytes(packet)
                    audio_stream_file.write(packet_bytes)
                except Exception:
                    pass

            audio_offset_accumulator += packet.size
        elif packet.stream.type == 'subtitle':
            packet_stream_offset = last_video_offset + audio_offset_accumulator + subtitle_offset_accumulator

            if save_stream and subtitle_stream_file:
                try:
                    packet_bytes = bytes(packet)
                    subtitle_stream_file.write(packet_bytes)
                except Exception:
                    pass

            subtitle_offset_accumulator += packet.size

        if packet.stream.type == 'video':
            frames = []
            packet_bytes = bytes(packet)
            frame_type_info = _get_h264_frame_type(packet_bytes)
            frame_type_str = frame_type_info[0]
            sei_nal_offsets = _scan_h264_sei_nal_units(packet_bytes)
            sei_raw = b''.join(packet_bytes[lo:hi] for lo, hi in sei_nal_offsets) if sei_nal_offsets else b''
            if sei_nal_offsets and save_stream and sei_stream_file:
                try:
                    sei_stream_file.write(sei_raw)
                except Exception:
                    pass
            try:
                frames = list(packet.decode())
            except (av.InvalidDataError, av.EOFError, av.ExternalError,
                    av.BugError, av.BufferTooSmallError) as decode_error:
                # Capture PyAV-specific corruption and decoding errors
                if forensic_mode:
                    packet_index = len(packets) + len(corrupted_packets)
                    corrupted_packets.append(CorruptedPacketInfo(
                        packet_index=packet_index,
                        stream_offset=packet_stream_offset,
                        timestamp=packet.pts if packet.pts else 'unknown',
                        size=packet.size,
                        error=str(decode_error),
                        error_type=type(decode_error).__name__,
                        frame_type=frame_type_str,
                        packet_data=packet_bytes
                    ))
                    if hex_dump_dir and packet_stream_offset >= 0:
                        _save_hex_dump(hex_dump_dir, packet_stream_offset, packet_bytes, frame_type_info)
                continue
            except av.FFmpegError as decode_error:
                # Catch other FFmpeg errors
                if forensic_mode:
                    packet_index = len(packets) + len(corrupted_packets)
                    corrupted_packets.append(CorruptedPacketInfo(
                        packet_index=packet_index,
                        stream_offset=packet_stream_offset,
                        timestamp=packet.pts if packet.pts else 'unknown',
                        size=packet.size,
                        error=str(decode_error),
                        error_type=type(decode_error).__name__,
                        frame_type=frame_type_str,
                        packet_data=packet_bytes
                    ))
                    # Save hex dump of corrupted packet
                    if hex_dump_dir and packet_stream_offset >= 0:
                        _save_hex_dump(hex_dump_dir, packet_stream_offset, packet_bytes, frame_type_info)
                continue
            except Exception as decode_error:
                # Catch other unexpected errors
                if forensic_mode:
                    packet_index = len(packets) + len(corrupted_packets)
                    corrupted_packets.append(CorruptedPacketInfo(
                        packet_index=packet_index,
                        stream_offset=packet_stream_offset,
                        timestamp=packet.pts if packet.pts else 'unknown',
                        size=packet.size,
                        error=str(decode_error),
                        error_type=type(decode_error).__name__,
                        frame_type=frame_type_str,
                        packet_data=packet_bytes
                    ))
                    # Save hex dump of corrupted packet
                    if hex_dump_dir and packet_stream_offset >= 0:
                        _save_hex_dump(hex_dump_dir, packet_stream_offset, packet_bytes, frame_type_info)
                continue

            # Check if frames were actually decoded (forensic check)
            if forensic_mode and len(frames) == 0 and packet.size > 0:
                # Packet had data but produced no decoded frames - likely corruption
                packet_index = len(packets) + len(corrupted_packets)
                corrupted_packets.append(CorruptedPacketInfo(
                    packet_index=packet_index,
                    stream_offset=packet_stream_offset,
                    timestamp=packet.pts if packet.pts else 'unknown',
                    size=packet.size,
                    error=str(decode_error),
                    error_type=type(decode_error).__name__,
                    frame_type=frame_type_str,
                    packet_data=packet_bytes
                ))

                # Save hex dump of corrupted packet
                if hex_dump_dir and packet_stream_offset >= 0:
                    _save_hex_dump(hex_dump_dir, packet_stream_offset, packet_bytes, frame_type_info)

            for frame in frames:
                if frame.pts is None:
                    continue
                
                current_wall_time = time.time()
                if first_frame_wall_time is None:
                    first_frame_wall_time = current_wall_time

                timestamp = frame.pts * video_stream.time_base * 1000
                if first_pts is None:
                    first_pts = timestamp
                
                relative_timestamp = timestamp - first_pts
                expected_time = first_frame_wall_time + relative_timestamp / 1000.0
                drift = (current_wall_time - expected_time) * 1000
                
                frame_type = av.video.frame.PictureType(frame.pict_type).name

                # Convert wall clock time to milliseconds for consistency
                wall_clock_ms = current_wall_time * 1000

                packet_num = len(packets)
                packets.append(PacketInfo(
                    type=frame_type,
                    wall_clock=wall_clock_ms,
                    stream_offset=packet_stream_offset,
                    packet_number=packet_num,
                    timestamp=timestamp,
                    size=packet.size,
                    drift=drift,
                    sei_metadata=sei_raw.hex() if sei_nal_offsets else "",
                    subtitle_data=""
                ))


                if log_file:
                    packet_num = len(packets)
                    log_file.write(f"{wall_clock_ms:.2f},0x{packet_stream_offset:08x},{packet_stream_offset},{packet_num},{frame_type},{packet.size},{timestamp:.2f},{drift:.2f}\n")
        elif packet.stream.type == 'audio':
            if packet.pts is not None:
                current_audio_wall_time = time.time()
                if first_audio_wall_time is None:
                    first_audio_wall_time = current_audio_wall_time

                timestamp = packet.pts * audio_stream.time_base * 1000
                if first_audio_pts is None:
                    first_audio_pts = timestamp

                relative_timestamp = timestamp - first_audio_pts
                expected_time = first_audio_wall_time + relative_timestamp / 1000.0
                drift = (current_audio_wall_time - expected_time) * 1000

                # Convert wall clock time to milliseconds for consistency
                audio_wall_clock_ms = current_audio_wall_time * 1000

                packet_num = len(packets)
                packets.append(PacketInfo(
                    type='A',
                    wall_clock=audio_wall_clock_ms,
                    stream_offset=packet_stream_offset,
                    packet_number=packet_num,
                    timestamp=timestamp,
                    size=packet.size,
                    drift=drift,
                    sei_metadata="",
                    subtitle_data=""
                ))


                if log_file:
                    packet_num = len(packets)
                    log_file.write(f"{audio_wall_clock_ms:.2f},0x{packet_stream_offset:08x},{packet_stream_offset},{packet_num},A,{packet.size},{timestamp:.2f},{drift:.2f}\n")
        elif packet.stream.type == 'subtitle':
            if packet.pts is not None:
                current_subtitle_wall_time = time.time()
                if first_subtitle_wall_time is None:
                    first_subtitle_wall_time = current_subtitle_wall_time

                timestamp = packet.pts * subtitle_stream.time_base * 1000
                if first_subtitle_pts is None:
                    first_subtitle_pts = timestamp

                relative_timestamp = timestamp - first_subtitle_pts
                expected_time = first_subtitle_wall_time + relative_timestamp / 1000.0
                drift = (current_subtitle_wall_time - expected_time) * 1000

                subtitle_wall_clock_ms = current_subtitle_wall_time * 1000

                subtitle_text = ""
                try:
                    subtitle_frames = list(packet.decode())
                    for sf in subtitle_frames:
                        if hasattr(sf, 'ass_encoded') and sf.ass_encoded:
                            subtitle_text += sf.ass_encoded + "\n"
                        elif hasattr(sf, 'text') and sf.text:
                            subtitle_text += sf.text + "\n"
                except Exception:
                    pass

                packet_num = len(packets)
                packets.append(PacketInfo(
                    type='S',
                    wall_clock=subtitle_wall_clock_ms,
                    stream_offset=packet_stream_offset,
                    packet_number=packet_num,
                    timestamp=timestamp,
                    size=packet.size,
                    drift=drift,
                    sei_metadata="",
                    subtitle_data=subtitle_text.strip()
                ))

                if log_file:
                    packet_num = len(packets)
                    log_file.write(f"{subtitle_wall_clock_ms:.2f},0x{packet_stream_offset:08x},{packet_stream_offset},{packet_num},S,{packet.size},{timestamp:.2f},{drift:.2f}\n")

    end_time = time.time()
    actual_duration = end_time - start_time

    # Close stream files
    if log_file:
        log_file.close()
        print(f"Flow data saved to {os.path.join(stream_output_dir, 'flow.csv')}")


    if save_stream and raw_stream_file:
        try:
            raw_stream_file.close()
            file_size = os.path.getsize(raw_stream_filename)
            print(f"✓ Raw stream saved successfully! ({file_size} bytes)")
        except Exception as e:
            print(f"Warning: Error closing raw stream file: {e}")

    if save_stream and video_stream_file:
        try:
            video_stream_file.close()
            file_size = os.path.getsize(video_stream_filename)
            print(f"✓ Video stream saved successfully! ({file_size} bytes)")
        except Exception as e:
            print(f"Warning: Error closing video stream file: {e}")

    if save_stream and audio_stream_file:
        try:
            audio_stream_file.close()
            file_size = os.path.getsize(audio_stream_filename)
            print(f"✓ Audio stream saved successfully! ({file_size} bytes)")
        except Exception as e:
            print(f"Warning: Error closing audio stream file: {e}")

    if save_stream and subtitle_stream_file:
        try:
            subtitle_stream_file.close()
            file_size = os.path.getsize(subtitle_stream_filename)
            print(f"✓ Subtitle stream saved successfully! ({file_size} bytes)")
        except Exception as e:
            print(f"Warning: Error closing subtitle stream file: {e}")

    if save_stream and sei_stream_file:
        try:
            sei_stream_file.close()
            file_size = os.path.getsize(sei_stream_filename)
            print(f"✓ SEI data saved successfully! ({file_size} bytes)")
        except Exception as e:
            print(f"Warning: Error closing SEI file: {e}")



    # Sort packets by wall clock time
    packets.sort(key=lambda p: p.wall_clock)

    video_packets = [p for p in packets if p.type in ['I', 'P', 'B']]
    audio_packets = [p for p in packets if p.type == 'A']
    subtitle_packets = [p for p in packets if p.type == 'S']

    report_lines.append(f"Analysis duration: {actual_duration:.2f} seconds")
    report_lines.append("" * 30)
    report_lines.append("Video Analysis")
    report_lines.append(f"Total frames captured: {len(video_packets)}")

    if actual_duration > 0:
        avg_fps = len(video_packets) / actual_duration
        report_lines.append(f"Average FPS: {avg_fps:.2f}")
    else:
        report_lines.append("No frames captured.")

    if video_packets:
        frame_types = [p.type for p in video_packets]
        frame_type_counts = Counter(frame_types)
        report_lines.append("Frame Type Distribution:")
        for f_type, count in frame_type_counts.items():
            report_lines.append(f"  - {f_type}: {count}")

        timestamps = [p.timestamp for p in video_packets]
        if len(timestamps) > 1:
            timestamp_diffs = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            avg_timestamp_diff = sum(timestamp_diffs) / len(timestamp_diffs)
            report_lines.append(f"Average timestamp difference: {avg_timestamp_diff:.2f} ms")
            
            non_monotonic = [i for i, diff in enumerate(timestamp_diffs, 1) if diff < 0]
            if non_monotonic:
                report_lines.append(f"Warning: Non-monotonic timestamps found at frame indices: {non_monotonic}")
            else:
                report_lines.append("Timestamps are monotonic.")

            skipped_frames_threshold = avg_timestamp_diff * 2
            skipped_frames = [i for i, diff in enumerate(timestamp_diffs, 1) if diff > skipped_frames_threshold]
            if skipped_frames:
                report_lines.append(f"Warning: Potential skipped frames detected at frame indices: {skipped_frames}")
            else:
                report_lines.append("No significant timestamp gaps detected.")
            
            drifts = [p.drift for p in video_packets]
            avg_drift = sum(drifts) / len(drifts)
            max_drift = max(drifts, key=abs)
            report_lines.append(f"Average wall clock drift: {avg_drift:.2f} ms")
            report_lines.append(f"Max wall clock drift: {max_drift:.2f} ms")

        frame_sizes = [p.size for p in video_packets]
        avg_frame_size = sum(frame_sizes) / len(frame_sizes)
        min_frame_size = min(frame_sizes)
        max_frame_size = max(frame_sizes)
        report_lines.append(f"Average compressed frame size: {avg_frame_size / 1024:.2f} KB")
        report_lines.append(f"Min compressed frame size: {min_frame_size / 1024:.2f} KB")
        report_lines.append(f"Max compressed frame size: {max_frame_size / 1024:.2f} KB")

    if audio_stream:
        report_lines.append("" * 30)
        report_lines.append("Audio Analysis")
        report_lines.append(f"Total audio packets: {len(audio_packets)}")
        if actual_duration > 0:
            avg_pps = len(audio_packets) / actual_duration
            report_lines.append(f"Average packets per second: {avg_pps:.2f}")
        if audio_packets:
            audio_packet_sizes = [p.size for p in audio_packets]
            avg_audio_size = sum(audio_packet_sizes) / len(audio_packet_sizes)
            min_audio_size = min(audio_packet_sizes)
            max_audio_size = max(audio_packet_sizes)
            report_lines.append(f"Average packet size: {avg_audio_size:.2f} bytes")
            report_lines.append(f"Min packet size: {min_audio_size} bytes")
            report_lines.append(f"Max packet size: {max_audio_size} bytes")
            
            audio_drifts = [p.drift for p in audio_packets]
            avg_audio_drift = sum(audio_drifts) / len(audio_drifts)
            max_audio_drift = max(audio_drifts, key=abs)
            report_lines.append(f"Average wall clock drift: {avg_audio_drift:.2f} ms")
            report_lines.append(f"Max wall clock drift: {max_audio_drift:.2f} ms")

    if subtitle_stream and subtitle_packets:
        report_lines.append("-" * 30)
        report_lines.append("Subtitle Analysis")
        report_lines.append(f"Total subtitle packets: {len(subtitle_packets)}")
        if actual_duration > 0:
            avg_sps = len(subtitle_packets) / actual_duration
            report_lines.append(f"Average packets per second: {avg_sps:.2f}")

    # Add forensic corruption analysis if enabled
    if forensic_mode and corrupted_packets:
        report_lines.append("-" * 30)
        report_lines.append("FORENSIC CORRUPTION ANALYSIS")
        report_lines.append(f"Total corrupted packets detected: {len(corrupted_packets)}")
        report_lines.append("")

        # Error type descriptions
        error_descriptions = {
            'InvalidDataError': 'Invalid data found when processing input (H.264 bitstream corruption)',
            'EOFError': 'End of file reached unexpectedly',
            'ExternalError': 'Generic error in external library (FFmpeg)',
            'BugError': 'Internal bug in FFmpeg decoder',
            'BufferTooSmallError': 'Buffer too small for decoded data',
            'NoFramesDecoded': 'Packet produced no decoded frames (silent corruption)',
        }

        # Group errors by type
        error_types = Counter([p.error_type for p in corrupted_packets])
        report_lines.append("Corruption Types:")
        for error_type, count in error_types.items():
            description = error_descriptions.get(error_type, error_type)
            report_lines.append(f"  - {error_type}: {count} occurrences")
            report_lines.append(f"    ({description})")

        report_lines.append("")
        report_lines.append("Detailed Corruption Events:")
        for i, corrupt_pkt in enumerate(corrupted_packets[:20], 1):  # Show first 20
            report_lines.append(f"  [{i}] Packet #{corrupt_pkt.packet_index}")
            report_lines.append(f"      Timestamp: {corrupt_pkt.timestamp}")
            report_lines.append(f"      Size: {corrupt_pkt.size} bytes")
            report_lines.append(f"      Frame Type: {corrupt_pkt.frame_type}")
            report_lines.append(f"      Error Type: {corrupt_pkt.error_type}")
            report_lines.append(f"      Error: {corrupt_pkt.error[:100]}")

        if len(corrupted_packets) > 20:
            report_lines.append(f"  ... and {len(corrupted_packets) - 20} more corrupted packets")

        # Save corrupted packets to separate file
        corruption_report_path = os.path.join(stream_output_dir, "corruption.txt")
        with open(corruption_report_path, "w") as f:
            f.write("DETAILED CORRUPTION FORENSIC REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Stream: {rtsp_url}\n")
            f.write("=" * 60 + "\n\n")

            for i, corrupt_pkt in enumerate(corrupted_packets, 1):
                f.write(f"Corrupted Packet #{i}\n")
                f.write(f"  Packet Index: {corrupt_pkt.packet_index}\n")
                stream_offset = corrupt_pkt.stream_offset
                if stream_offset >= 0:
                    f.write(f"  Stream Offset: 0x{stream_offset:08x} ({stream_offset} bytes)\n")
                f.write(f"  Timestamp (PTS): {corrupt_pkt.timestamp}\n")
                f.write(f"  Packet Size: {corrupt_pkt.size} bytes\n")
                f.write(f"  Frame Type: {corrupt_pkt.frame_type}\n")
                f.write(f"  Error Type: {corrupt_pkt.error_type}\n")
                f.write(f"  Error Description: {corrupt_pkt.error}\n")
                if stream_offset >= 0:
                    f.write(f"  Hex Dump: {stream_offset:08x}.hex\n")
                    f.write(f"  Binary: {stream_offset:08x}.bin\n")
                f.write("-" * 60 + "\n\n")

        print(f"Corruption report saved to {corruption_report_path}")
    elif forensic_mode:
        report_lines.append("-" * 30)
        report_lines.append("FORENSIC CORRUPTION ANALYSIS")
        report_lines.append("No corrupted packets detected.")

    report_lines.append("-" * 30)
    report_lines.append("Analysis finished.")

    report = "\n".join(report_lines)
    print(report)

    report_path = os.path.join(stream_output_dir, "report.txt")
    with open(report_path, "w") as f:
        f.write(report)

    print(f"Report saved to {report_path}")
    print(f"All files saved to: {stream_output_dir}")

    # Return data as pandas DataFrame for chart generation
    if packets:
        # Create DataFrame from packets data
        df_data = []
        for i, packet in enumerate(packets, 1):
            df_data.append({
                'Packet': i,
                'Type': packet.type,
                'Timestamp (ms)': packet.timestamp,
                'Wall Clock Time (ms)': packet.wall_clock,
                'Drift (ms)': packet.drift,
                'Packet Size (bytes)': packet.size,
                'Has SEI': bool(getattr(packet, 'sei_metadata', '')),
                'Subtitle': getattr(packet, 'subtitle_data', '')
            })


        # Close stream file if it was opened
        if save_stream and raw_stream_file:
            try:
                raw_stream_file.close()
                file_size = os.path.getsize(raw_stream_filename)
                print(f"✓ Stream saved successfully! ({file_size} bytes)")
            except Exception as e:
                print(f"Warning: Error closing stream file: {e}")

        container.close()
        return pd.DataFrame(df_data), stream_output_dir
    else:
        # Close stream file if it was opened
        if save_stream and raw_stream_file:
            try:
                raw_stream_file.close()
                file_size = os.path.getsize(raw_stream_filename)
                print(f"✓ Stream saved (no analysis data collected) ({file_size} bytes)")
            except Exception as e:
                print(f"Warning: Error closing stream file: {e}")

        container.close()
        return None, stream_output_dir

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RTSP Stream Forensic Analyzer")
    parser.add_argument("url", help="RTSP stream URL")
    parser.add_argument("--user", help="Username for RTSP authentication", default="")
    parser.add_argument("--password", help="Password for RTSP authentication", default="")
    parser.add_argument("--duration", type=int, default=30, help="Duration of analysis in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable per-frame debug logging")
    
    args = parser.parse_args()

    if args.user and args.password:
        url_parts = args.url.split("://")
        if len(url_parts) == 2:
            if "@" in url_parts[1]:
                host_path = url_parts[1].split("@")[-1]
            else:
                host_path = url_parts[1]
            full_url = f"{url_parts[0]}://{args.user}:{args.password}@{host_path}"
        else:
            print(f"Error: Could not parse URL to insert credentials.")
            exit(1)
    else:
        full_url = args.url

    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = sanitize_url_for_filename(args.url)
    os.makedirs(output_dir, exist_ok=True)

    analyze_rtsp_stream(full_url, args.duration, output_dir, args.debug, timestamp_prefix)