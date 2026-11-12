"""
Módulo de Teoria Musical, Conversão de Frequências e Transposição Automática de Cifras (`fast-helper`).
Converte frequências fundamentais (Hz) em notas musicais, oitavas e desvios (cents),
além de detectar o tom de cifras coladas e transpô-las automaticamente para o tom cadastrado.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass

NOTE_NAMES_EN: tuple[str, ...] = (
    "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"
)

NOTE_NAMES_FLATS_EN: tuple[str, ...] = (
    "C", "Db", "D", "Eb", "E", "F", "Gb", "G", "Ab", "A", "Bb", "B"
)

NOTE_NAMES_PT: tuple[str, ...] = (
    "Dó", "Dó#", "Ré", "Ré#", "Mi", "Fá", "Fá#", "Sol", "Sol#", "Lá", "Lá#", "Si"
)

NOTE_TO_INDEX: dict[str, int] = {
    "C": 0, "B#": 0,
    "C#": 1, "DB": 1, "Db": 1,
    "D": 2,
    "D#": 3, "EB": 3, "Eb": 3,
    "E": 4, "FB": 4, "Fb": 4,
    "F": 5, "E#": 5,
    "F#": 6, "GB": 6, "Gb": 6,
    "G": 7,
    "G#": 8, "AB": 8, "Ab": 8,
    "A": 9,
    "A#": 10, "BB": 10, "Bb": 10,
    "B": 11, "CB": 11, "Cb": 11,
}

FLAT_KEYS: set[str] = {
    "F", "Bb", "Eb", "Ab", "Db", "Gb",
    "Dm", "Gm", "Cm", "Fm", "Bbm", "Ebm",
}

CHORD_CORE_PATTERN = (
    r"[A-G](?:#|b)?(?:m|maj|min|dim|aug|sus|add|\+|\-|º|°|\([#b+\-0-9M/a-zA-Z]+\)|b5|\/[0-9]+|[0-9M/\-])*(?:\/[A-G](?:#|b)?)?"
)
CHORD_REGEX = re.compile(f"^{CHORD_CORE_PATTERN}$")


@dataclass(frozen=True)
class PitchNote:
    """Representa uma nota musical extraída de uma frequência em Hz."""
    frequency_hz: float
    midi_number: int
    pitch_class: int  # 0 (C) a 11 (B)
    note_en: str      # ex: "G"
    note_pt: str      # ex: "Sol"
    octave: int       # ex: 3
    cents_offset: float  # Desvio entre -50.0 e +50.0 cents
    nominal_frequency_hz: float = 0.0  # Frequência padrão exata da nota (ex: 440.0 para A4)

    @property
    def full_name_en(self) -> str:
        return f"{self.note_en}{self.octave}"

    @property
    def full_name_pt(self) -> str:
        return f"{self.note_pt}{self.octave}"


def clean_chord_sheet(sheet_text: str) -> str:
    """Remove tags HTML, quebras de linha Windows/Mac e caracteres invisíveis."""
    if not sheet_text or not isinstance(sheet_text, str):
        return ""
    text = sheet_text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(p|div)>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("\u00a0", " ")
    text = re.sub(r"[\u200b-\u200d\ufeff]", "", text)
    return text


def frequency_to_note(frequency_hz: float, a4_hz: float = 440.0) -> PitchNote:
    """
    Converte uma frequência em Hz para a nota musical mais próxima (padrão A4 = 440 Hz).
    Lança ValueError se a frequência for <= 0.
    """
    if frequency_hz <= 0 or math.isnan(frequency_hz) or math.isinf(frequency_hz):
        raise ValueError("A frequência deve ser um número positivo maior que zero.")

    exact_midi = 69.0 + 12.0 * math.log2(frequency_hz / a4_hz)
    nearest_midi = int(round(exact_midi))
    nominal_hz = a4_hz * (2.0 ** ((nearest_midi - 69.0) / 12.0))
    cents = (exact_midi - nearest_midi) * 100.0

    pitch_class = nearest_midi % 12
    octave = (nearest_midi // 12) - 1

    return PitchNote(
        frequency_hz=round(frequency_hz, 2),
        midi_number=nearest_midi,
        pitch_class=pitch_class,
        note_en=NOTE_NAMES_EN[pitch_class],
        note_pt=NOTE_NAMES_PT[pitch_class],
        octave=octave,
        cents_offset=round(cents, 1),
        nominal_frequency_hz=round(nominal_hz, 2),
    )


def relative_minor_or_major(pitch_class: int, is_major: bool) -> tuple[str, str]:
    """
    Retorna a tonalidade relativa (Menor se a atual for Maior, ou Maior se for Menor)
    nos formatos (Inglês, Português).
    """
    if is_major:
        rel_idx = (pitch_class - 3) % 12
        return f"{NOTE_NAMES_EN[rel_idx]}m", f"{NOTE_NAMES_PT[rel_idx]} Menor"
    else:
        rel_idx = (pitch_class + 3) % 12
        return f"{NOTE_NAMES_EN[rel_idx]}", f"{NOTE_NAMES_PT[rel_idx]} Maior"


def _strip_accents(text: str) -> str:
    return "".join(
        c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn"
    )


def parse_musical_key(raw_tone: str) -> dict | None:
    """
    Interpreta formatos de tom como 'E - MI', 'E (Mi)', 'Sol', 'G', 'F#m (Fá#m)', 'Bb'.
    Retorna dicionário com root, is_minor, index, canonical, prefer_flats.
    """
    if not raw_tone or not isinstance(raw_tone, str):
        return None

    first_segment = raw_tone.split(",")[0].strip()
    if not first_segment:
        return None

    clean = _strip_accents(first_segment).strip()
    root_en: str | None = None
    is_minor = False

    pt_match = re.match(
        r"^(do|re|mi|fa|sol|la|si)(#|b)?(?:\s*(m|min|menor|maior|maj)(?![a-z]))?(?:\b|[\s\-\(\/]|$)",
        clean,
        re.IGNORECASE,
    )
    if pt_match:
        syllable = pt_match.group(1).lower()
        acc = ("b" if pt_match.group(2).lower() == "b" else "#") if pt_match.group(2) else ""
        qual = (pt_match.group(3) or "").lower()
        pt_to_en = {
            "do": "C",
            "re": "D",
            "mi": "E",
            "fa": "F",
            "sol": "G",
            "la": "A",
            "si": "B",
        }
        root_en = f"{pt_to_en[syllable]}{acc}"
        is_minor = qual in ("m", "min", "menor")
    else:
        en_match = re.match(
            r"^([A-G])(#|b)?(?:(m|min|menor|maj|maior)(?![a-z]))?(?:[0-9]|sus|add|dim|\+|\-)*(?:\/[A-G](?:#|b)?)?(?:\b|[\s\-\(\/]|$)",
            clean,
            re.IGNORECASE,
        )
        if en_match:
            letter = en_match.group(1).upper()
            acc = ("b" if en_match.group(2).lower() == "b" else "#") if en_match.group(2) else ""
            qual = (en_match.group(3) or "").lower()
            root_en = f"{letter}{acc}"
            is_minor = qual in ("m", "min", "menor")

    if not root_en:
        return None

    if not is_minor and re.search(r"\b(menor|minor)\b", clean, re.IGNORECASE):
        is_minor = True

    idx = NOTE_TO_INDEX.get(root_en, NOTE_TO_INDEX.get(root_en.upper()))
    if idx is None:
        return None

    prefer_flats = ("b" in root_en) or (f"{root_en}{'m' if is_minor else ''}" in FLAT_KEYS)
    norm_root = NOTE_NAMES_FLATS_EN[idx] if prefer_flats else NOTE_NAMES_EN[idx]
    canonical = f"{norm_root}{'m' if is_minor else ''}"

    return {
        "root": norm_root,
        "is_minor": is_minor,
        "index": idx,
        "canonical": canonical,
        "prefer_flats": canonical in FLAT_KEYS or ("b" in root_en),
    }


def normalize_musical_key(raw_tone: str) -> str:
    parsed = parse_musical_key(raw_tone)
    return parsed["canonical"] if parsed else raw_tone.strip()


def transpose_note(note: str, semitones: int, prefer_flats: bool = False) -> str:
    norm = note.strip()
    direct_idx = NOTE_TO_INDEX.get(norm, NOTE_TO_INDEX.get(norm.upper()))
    if direct_idx is not None:
        target_idx = (direct_idx + semitones) % 12
        use_flats = prefer_flats or ("b" in norm)
        return NOTE_NAMES_FLATS_EN[target_idx] if use_flats else NOTE_NAMES_EN[target_idx]

    parsed = parse_musical_key(norm)
    if not parsed:
        return note

    target_idx = (parsed["index"] + semitones) % 12
    target_root = NOTE_NAMES_FLATS_EN[target_idx] if prefer_flats else NOTE_NAMES_EN[target_idx]
    suffix = "m" if parsed["is_minor"] else ""
    canonical = f"{target_root}{suffix}"
    if canonical in FLAT_KEYS:
        return f"{NOTE_NAMES_FLATS_EN[target_idx]}{suffix}"
    return canonical


def transpose_chord(chord: str, semitones: int, prefer_flats: bool = False) -> str:
    if semitones == 0:
        return chord

    if "/" in chord:
        slash_idx = chord.find("/")
        main_part = chord[:slash_idx]
        bass_part = chord[slash_idx + 1:]
        if main_part and bass_part and re.match(r"^[A-G](?:#|b)?$", bass_part):
            return f"{transpose_chord(main_part, semitones, prefer_flats)}/{transpose_note(bass_part, semitones, prefer_flats)}"

    m = re.match(r"^([A-G](?:#|b)?)(.*)$", chord)
    if not m:
        return chord

    root, suffix = m.group(1), m.group(2)
    return f"{transpose_note(root, semitones, prefer_flats)}{suffix}"


def is_chord(token: str) -> bool:
    if not token or len(token) > 15:
        return False
    clean = token.strip()
    return bool(clean and CHORD_REGEX.match(clean))


def _is_auxiliary_token(token: str) -> bool:
    return bool(re.match(r"^(?:\(?[0-9]+x\)?|\||\-+|\/+|\•)$", token.strip(), re.IGNORECASE))


def is_chord_line(line: str) -> bool:
    trimmed = line.strip()
    if not trimmed:
        return False
    if re.match(r"^\[?\s*(?:tom(?:\s+original)?|tone|key)\s*:", trimmed, re.IGNORECASE):
        return False
    if re.match(r"^\[[^\]]+\]$", trimmed):
        return False
    if re.match(r"^[eEaAdDgGbB]\|", trimmed):
        return False

    without_section = re.sub(r"^(\[[^\]]+\]|[A-Za-z0-9_\u00c0-\u00ff\s]{1,12}:)\s*", "", trimmed).strip()
    if not without_section:
        return False

    raw_tokens = [t for t in without_section.split() if t]
    meaningful = [t for t in raw_tokens if not _is_auxiliary_token(t)]
    if not meaningful:
        return False

    chord_count = sum(1 for t in meaningful if is_chord(t))
    return (chord_count / len(meaningful)) >= 0.5


def _transpose_chord_line_preserving_columns(line: str, semitones: int, prefer_flats: bool) -> str:
    sec_match = re.match(r"^(\s*\[[^\]]+\]\s*|\s*[A-Za-z0-9_\u00c0-\u00ff\s]{1,12}:\s*)(.*)$", line)
    prefix = sec_match.group(1) if sec_match else ""
    body = sec_match.group(2) if sec_match else line

    token_re = re.compile(f"({CHORD_CORE_PATTERN})( +|$)")

    def _repl(match: re.Match) -> str:
        full_match = match.group(0)
        chord_token = match.group(1)
        trailing_spaces = match.group(2)
        start_pos = match.start()
        if start_pos > 0 and not body[start_pos - 1].isspace():
            return full_match
        if not is_chord(chord_token):
            return full_match

        transposed = transpose_chord(chord_token, semitones, prefer_flats)
        if not trailing_spaces:
            return transposed
        if len(trailing_spaces) > 1:
            len_diff = len(transposed) - len(chord_token)
            adjusted = max(1, len(trailing_spaces) - len_diff)
            return transposed + (" " * adjusted)
        return transposed + trailing_spaces

    return prefix + token_re.sub(_repl, body)


def transpose_chord_sheet(sheet_text: str, semitones: int, prefer_flats: bool = False) -> str:
    if not sheet_text or semitones == 0:
        return sheet_text

    cleaned = clean_chord_sheet(sheet_text)
    out_lines: list[str] = []
    for line in cleaned.split("\n"):
        tom_m = re.match(
            r"^(\s*\[?\s*(?:tom(?:\s+original)?|tone|key)\s*:\s*)([^\n\]]+?)(\s*\]?\s*)$",
            line,
            re.IGNORECASE,
        )
        if tom_m:
            parsed_tom = parse_musical_key(tom_m.group(2))
            if parsed_tom:
                new_tom = transpose_note(parsed_tom["canonical"], semitones, prefer_flats)
                out_lines.append(f"{tom_m.group(1)}{new_tom}{tom_m.group(3)}")
                continue

        if is_chord_line(line):
            out_lines.append(_transpose_chord_line_preserving_columns(line, semitones, prefer_flats))
            continue

        if "[" in line and "]" in line:
            def _bracket_repl(bm: re.Match) -> str:
                inside = bm.group(1).strip()
                if is_chord(inside):
                    return f"[{transpose_chord(inside, semitones, prefer_flats)}]"
                return bm.group(0)

            out_lines.append(re.sub(r"\[([^\]]+)\]", _bracket_repl, line))
            continue

        out_lines.append(line)

    return "\n".join(out_lines)


def extract_all_chords_in_order(sheet_text: str) -> list[str]:
    if not sheet_text:
        return []
    cleaned = clean_chord_sheet(sheet_text)
    chords: list[str] = []
    token_re = re.compile(f"(?:^|\\s)({CHORD_CORE_PATTERN})(?=\\s|$)")

    for line in cleaned.split("\n"):
        if is_chord_line(line):
            without_sec = re.sub(r"^(\[[^\]]+\]|[A-Za-z0-9_\u00c0-\u00ff\s]{1,12}:)\s*", "", line.strip())
            pos = 0
            while pos < len(without_sec):
                m = token_re.search(without_sec, pos)
                if not m:
                    break
                cand = m.group(1).strip()
                if is_chord(cand):
                    chords.append(cand)
                pos = m.end()
            continue

        if "[" in line and "]" in line:
            for bm in re.finditer(r"\[([^\]]+)\]", line):
                inside = bm.group(1).strip()
                if is_chord(inside):
                    chords.append(inside)

    return chords


def detect_chord_sheet_key(sheet_text: str, target_is_minor: bool = False) -> str | None:
    if not sheet_text or not sheet_text.strip():
        return None

    cleaned = clean_chord_sheet(sheet_text)

    explicit_m = re.search(
        r"^\s*\[?\s*(?:tom(?:\s+original)?|tone|key)\s*:\s*([^\n\]]+?)\s*\]?\s*$",
        cleaned,
        re.IGNORECASE | re.MULTILINE,
    )
    if explicit_m:
        explicit_parsed = parse_musical_key(explicit_m.group(1))
        if explicit_parsed:
            return explicit_parsed["canonical"]

    chord_tokens = extract_all_chords_in_order(cleaned)
    if not chord_tokens:
        return None

    parsed_chords = []
    for token in chord_tokens:
        parts = token.strip().split("/")
        main_p = parts[0]
        bass_p = parts[1] if len(parts) == 2 else None
        m = re.match(r"^([A-G](?:#|b)?)(.*)$", main_p)
        if not m:
            continue
        r_str, suffix = m.group(1), m.group(2) or ""
        r_idx = NOTE_TO_INDEX.get(r_str, NOTE_TO_INDEX.get(r_str.upper()))
        if r_idx is None:
            continue
        is_dim = bool(re.search(r"dim|º|°|m7\(b5\)|m7b5", suffix, re.IGNORECASE))
        is_min = (not is_dim) and bool(re.match(r"^m(?!aj)", suffix, re.IGNORECASE))
        b_idx = NOTE_TO_INDEX.get(bass_p, NOTE_TO_INDEX.get(bass_p.upper())) if bass_p else None
        parsed_chords.append((r_idx, b_idx, is_min, is_dim))

    if not parsed_chords:
        return None

    first_c = parsed_chords[0]
    last_c = parsed_chords[-1]
    total_c = len(parsed_chords)
    major_scale_intervals = {0, 2, 4, 5, 7, 9, 11}

    best_tonic = 0
    best_score = float("-inf")

    for tonic in range(12):
        score = 0.0
        has_i = has_iv = has_v = has_vi = False

        for r_idx, b_idx, is_min, is_dim in parsed_chords:
            interval = (r_idx - tonic) % 12
            if interval == 0 and not is_min and not is_dim:
                score += 4.0
                has_i = True
            elif interval == 5 and not is_min and not is_dim:
                score += 3.2
                has_iv = True
            elif interval == 7 and not is_min and not is_dim:
                score += 3.2
                has_v = True
            elif interval == 9 and is_min:
                score += 3.0
                has_vi = True
            elif interval == 2 and is_min:
                score += 2.5
            elif interval == 4 and is_min:
                score += 2.2
            elif interval == 11 and is_dim:
                score += 2.0
            else:
                score -= 1.8

            if b_idx is not None:
                if ((b_idx - tonic) % 12) in major_scale_intervals:
                    score += 1.0
                else:
                    score -= 1.2

        cadence_scale = max(1.0, total_c / 6.0)
        if has_i and has_iv and has_v:
            score += 12.0 * cadence_scale
        elif has_iv and has_v and has_vi:
            score += 10.0 * cadence_scale
        elif has_i and (has_iv or has_v):
            score += 4.5 * cadence_scale

        first_int = (first_c[0] - tonic) % 12
        if first_int == 0 and not first_c[2] and not first_c[3]:
            score += max(10.0, total_c * 1.0)
        elif first_int == 9 and first_c[2] and target_is_minor:
            score += max(8.0, total_c * 0.8)
        elif first_int == 5 and not first_c[2]:
            score += max(2.0, total_c * 0.2)

        last_int = (last_c[0] - tonic) % 12
        if last_int == 0 and not last_c[2] and not last_c[3]:
            score += max(5.0, total_c * 0.5)
        elif last_int == 9 and last_c[2] and target_is_minor:
            score += max(4.0, total_c * 0.4)

        if score > best_score:
            best_score = score
            best_tonic = tonic

    rel_minor = (best_tonic + 9) % 12
    if target_is_minor:
        if first_c[2] and last_c[2] and first_c[0] == last_c[0]:
            return f"{NOTE_NAMES_EN[first_c[0]]}m"
        return f"{NOTE_NAMES_EN[rel_minor]}m"

    return NOTE_NAMES_FLATS_EN[best_tonic] if NOTE_NAMES_FLATS_EN[best_tonic] in FLAT_KEYS else NOTE_NAMES_EN[best_tonic]


def calculate_semitone_difference(from_tone: str, to_tone: str) -> int:
    p_from = parse_musical_key(from_tone)
    p_to = parse_musical_key(to_tone)
    if not p_from or not p_to:
        return 0
    diff = (p_to["index"] - p_from["index"]) % 12
    if diff > 6:
        diff -= 12
    if diff < -6:
        diff += 12
    return diff


def auto_transpose_chord_sheet_to_key(sheet_text: str, target_tone_raw: str) -> tuple[str, str | None, str | None, int]:
    """
    Detecta o tom da cifra e a transpõe automaticamente para o tom cadastrado pelo usuário.
    Retorna (cifra_transposta, tom_detectado, tom_destino_canonico, semitons).
    """
    if not sheet_text or not sheet_text.strip() or not target_tone_raw or not target_tone_raw.strip():
        return sheet_text, None, None, 0

    cleaned = clean_chord_sheet(sheet_text)
    target_parsed = parse_musical_key(target_tone_raw)
    if not target_parsed:
        return cleaned, None, None, 0

    detected_key = detect_chord_sheet_key(cleaned, target_is_minor=target_parsed["is_minor"])
    if not detected_key:
        return cleaned, None, target_parsed["canonical"], 0

    semitones = calculate_semitone_difference(detected_key, target_parsed["canonical"])
    if semitones == 0:
        return cleaned, detected_key, target_parsed["canonical"], 0

    transposed = transpose_chord_sheet(cleaned, semitones, prefer_flats=target_parsed["prefer_flats"])
    return transposed, detected_key, target_parsed["canonical"], semitones
