# Chatterbox Multilingual — Parameter-Driven Control Reference

Chatterbox by Resemble AI uses **numeric parameters** to control expressiveness
and pacing rather than inline tags or SSML. It reads plain text — inline tags
are ignored.

This is the simplest control model: two sliders shape the entire delivery.

---

## Control parameters

### `exaggeration` (0.0 – 2.0)

Controls speech expressiveness — how dramatic or neutral the delivery sounds.

| Range | Effect |
|---|---|
| `0.0 – 0.3` | Monotone, flat, robotic |
| `0.3 – 0.7` | Natural, conversational |
| **`0.5`** | **Default** — balanced expressiveness |
| `0.7 – 1.0` | Noticeably expressive, animated |
| `1.0 – 1.5` | Dramatic, voice-acting level |
| `1.5 – 2.0` | Highly exaggerated, theatrical |

**Side effect:** Higher exaggeration tends to speed up speech.

### `cfg_weight` (0.0 – 2.0)

Balances adherence to the text vs. creative interpretation of delivery.

| Range | Effect |
|---|---|
| `0.0 – 0.3` | Strict text adherence, slower pacing |
| **`0.5`** | **Default** — balanced |
| `0.5 – 1.0` | More flexible interpretation |
| `1.0 – 2.0` | Highly creative, may deviate from expected pacing |

**Tuning tip:** If the reference speaker talks fast, lower `cfg_weight` to
~0.3 for more deliberate pacing. When raising `exaggeration`, lower
`cfg_weight` to compensate for the speed increase.

---

## Python usage

```python
from chatterbox.tts import ChatterboxTTS
import torchaudio as ta

model = ChatterboxTTS.from_pretrained(device="cuda")

# Basic generation
wav = model.generate(
    "Welcome to the show! Today we have an incredible story to share.",
    audio_prompt_path="reference_voice.wav",
    exaggeration=0.7,
    cfg_weight=0.5,
)
ta.save("output.wav", wav, model.sr)
```

### Streaming generation

```python
audio_chunks = []
for audio_chunk, metrics in model.generate_stream(
    "This is a streaming synthesis example with custom voice.",
    audio_prompt_path="reference_voice.wav",
    exaggeration=0.7,
    cfg_weight=0.3,
    chunk_size=25,
):
    audio_chunks.append(audio_chunk)

import torch
final_audio = torch.cat(audio_chunks, dim=-1)
ta.save("output.wav", final_audio, model.sr)
```

---

## Recommended presets

| Use case | `exaggeration` | `cfg_weight` | Notes |
|---|---|---|---|
| Audiobook narration | 0.5 | 0.5 | Default — natural, clear |
| Podcast host | 0.6 | 0.5 | Slightly animated |
| Character voice acting | 1.0 | 0.4 | Dramatic but controlled pacing |
| Children's story | 1.2 | 0.3 | Very expressive, deliberate pace |
| Corporate voiceover | 0.3 | 0.6 | Professional, measured |
| Emotional monologue | 0.9 | 0.4 | High expression, slower delivery |
| Fast-talking character | 0.7 | 0.7 | Energetic and quick |

---

## Prosody control through text

Since Chatterbox doesn't support inline tags, shape delivery through the text
itself:

- **Punctuation:** ellipses for pauses, em dashes for interruptions, commas
  for breath points
- **Sentence length:** short sentences = punchy; long sentences = flowing
- **Word choice:** emotional words naturally affect the model's delivery
- **Exclamation/question marks:** shift energy and intonation

```python
# Punctuation-driven prosody
text = "Wait... are you serious?! That's— no. No, that can't be right."

wav = model.generate(
    text,
    audio_prompt_path="reference_voice.wav",
    exaggeration=0.8,
    cfg_weight=0.4,
)
```

---

## Tips

- **Start with defaults** (`exaggeration=0.5`, `cfg_weight=0.5`) and adjust
  from there
- **The reference audio matters** — Chatterbox clones the voice from a short
  clip, and the reference speaker's natural expressiveness influences the output
- **Don't use tags** — `[excited]`, `{pause}`, and SSML are all ignored
- Chatterbox Multilingual v3 supports 25 languages including 4 dialects
- MIT license — fully open source
- Emotion intensity is continuous, not discrete categories — fine-tune the
  slider to taste
