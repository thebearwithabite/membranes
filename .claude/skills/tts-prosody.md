---
description: >
  TTS prosody, timing, and expression control — general SSML guidance plus
  model-specific inline tag references. Trigger on: "prosody", "SSML",
  "speech timing", "TTS tags", "audio tags", "emotion tags", "pause tag",
  "emphasis", "pacing", "voice expression", "delivery control", "breath",
  "whisper tag", "speaking style", "stage direction", "inline tag",
  "exaggeration", "pronunciation control".
---

# TTS Prosody & Timing Control

How to control pacing, emotion, emphasis, pauses, and vocal delivery across
TTS models. This skill covers general SSML concepts and links to
model-specific references.

**Model-specific references live in `references/`** — load the one matching
the model being used.

---

## Model landscape

Modern TTS models fall into three prosody-control paradigms:

| Paradigm | How it works | Models |
|---|---|---|
| **Inline tags** | `[tag]` or `{tag}` markers placed directly in text | ElevenLabs v3, Fish Audio S2, Qwen3-TTS |
| **Prompt-driven** | Natural-language stage directions outside quoted dialogue | DramaBox |
| **Parameter-driven** | Numeric sliders control expressiveness and pacing | Chatterbox Multilingual |

Some models combine paradigms (e.g., Qwen3-TTS uses both natural-language
instructions and inline tags).

---

## General SSML reference

Standard SSML is supported by cloud TTS services (Google Cloud TTS, Amazon
Polly, Azure Speech) but **not by most modern neural TTS models** listed above.
Include this section only when working with SSML-compatible engines.

### Core SSML tags

```xml
<speak>
  <!-- Pause -->
  <break time="500ms"/>
  <break strength="strong"/>

  <!-- Emphasis -->
  <emphasis level="strong">important</emphasis>

  <!-- Prosody (rate, pitch, volume) -->
  <prosody rate="slow" pitch="+10%" volume="loud">
    Dramatic delivery.
  </prosody>

  <!-- Say-as (numbers, dates, etc.) -->
  <say-as interpret-as="cardinal">42</say-as>
  <say-as interpret-as="date" format="mdy">12/25/2026</say-as>

  <!-- Phoneme override -->
  <phoneme alphabet="ipa" ph="təˈmeɪtoʊ">tomato</phoneme>

  <!-- Sub (abbreviation expansion) -->
  <sub alias="World Wide Web Consortium">W3C</sub>

  <!-- Sentence/paragraph boundaries -->
  <s>Sentence one.</s>
  <p>Paragraph text.</p>
</speak>
```

### Break strength values

| Strength | Approximate duration |
|---|---|
| `none` | No pause |
| `x-weak` | ~100ms |
| `weak` | ~200ms |
| `medium` | ~400ms |
| `strong` | ~600ms |
| `x-strong` | ~1000ms |

### Prosody rate values

`x-slow`, `slow`, `medium`, `fast`, `x-fast`, or percentage (`+25%`, `-10%`).

### Prosody pitch values

`x-low`, `low`, `medium`, `high`, `x-high`, or semitones (`+2st`, `-3st`),
or percentage.

---

## Universal prosody techniques

These work across virtually all TTS models, including those that don't support
tags:

### Punctuation as prosody

| Technique | Effect |
|---|---|
| `...` (ellipsis) | Natural pause / trailing off |
| `—` (em dash) | Abrupt break or interruption |
| `!` | Increased energy and emphasis |
| `?` | Rising intonation |
| `,` | Short breath pause |
| Line breaks | Phrasing boundaries |

### Text structure for pacing

- **Short sentences** → faster, punchier delivery
- **Long compound sentences** → flowing, narrative delivery
- **Sentence fragments** → hesitant, interrupted feel
- **ALL CAPS** → emphasis (some models; use sparingly)
- **Repeated letters** ("Nooo", "Sooo") → drawn-out delivery

### Contextual phrasing

Writing the emotion into the text itself ("she whispered nervously", "he
exclaimed with joy") can prime the model's tone even without explicit tags.

---

## Choosing the right model

| Need | Best fit |
|---|---|
| Fine-grained word-level emotion control | Fish Audio S2 |
| Natural-language direction + acting | DramaBox |
| Balanced inline tags + instruction control | Qwen3-TTS |
| Production TTS with ecosystem (cloning, dictionaries) | ElevenLabs v3 |
| Simple expressiveness slider, voice cloning | Chatterbox |
| Traditional SSML pipeline | Google Cloud TTS, Azure, Polly |

---

## Model-specific references

Load the reference matching the model in use:

- `references/elevenlabs-v3.md` — Audio tags (no SSML), emotion/delivery/pacing
- `references/fish-audio-s2.md` — Open-domain `[bracket]` tags + `(paralanguage)` cues
- `references/qwen3-tts.md` — Natural-language instructions + 86 inline tags
- `references/dramabox.md` — Screenplay-style prompt format with stage directions
- `references/chatterbox.md` — Parameter-driven expressiveness (`exaggeration`, `cfg_weight`)
