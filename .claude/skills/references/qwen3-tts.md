# Qwen3-TTS — Inline Tags & Instruction Control Reference

Qwen3-TTS (and Qwen-Audio-3.0-TTS) uses a dual-control system:

1. **Natural-language instructions** — set overall role, emotion, pace, timbre,
   style, and accent
2. **86 inline tags** — fine-grained control at the phrase/word level for
   expressive transitions and non-verbal events

---

## Control layers

### Layer 1: Natural-language instructions (system/instruction prompt)

Set the overall delivery before the text:

```
Speak as a warm, friendly podcast host. Use a conversational pace with
natural pauses. Slight British accent. Medium energy level.
```

Instruction dimensions:
- **Role** — narrator, news anchor, podcast host, character
- **Emotion** — cheerful, melancholy, tense, calm
- **Pace** — slow and deliberate, fast-paced, natural
- **Timbre** — deep and resonant, bright and clear, raspy
- **Style** — formal, conversational, dramatic, whispering
- **Accent** — regional or language-specific

### Layer 2: Inline tags (in the text itself)

Place `[tag]` markers where a delivery shift, pause, breath, or vocal event
should occur:

```
[excited] I finally got the results back!
[gasp] [panicked] This... this cannot be happening!
```

---

## Inline tag categories

### Emotion shifts

`[excited]` `[angry]` `[sad]` `[surprised]` `[nervous]` `[calm]`
`[curious]` `[panicked]` `[tired]` `[hopeful]` `[frustrated]`
`[joyful]` `[fearful]` `[disgusted]` `[resigned]` `[tender]`

### Non-verbal events

`[laughing]` `[sighing]` `[gasp]` `[breathing]` `[coughing]`
`[crying]` `[sniffling]` `[yawning]` `[clearing throat]`
`[sobbing]` `[chuckling]`

### Delivery modifiers

`[whisper]` `[shouting]` `[muttering]` `[whispering]`
`[speaking softly]` `[raised voice]`

### Pacing

`[pause]` `[long pause]` `[hesitating]` `[rushed]` `[slowly]`
`[stammering]`

---

## Example scripts

### Multi-emotion narrative

```
[tired] [sighing] Another day of working until midnight.
[curious] Hm — who left this letter on my desk?
[gasp] [panicked] This... this cannot be happening!
```

### Conversational with natural events

```
[cheerful] Hey, great to see you!
[laughing] I can't believe you actually wore that.
[pause]
[curious] But seriously, how have you been?
[sighing] It's been a long week.
```

### Narration with atmosphere

```
[calm] The village slept under a blanket of snow.
[pause]
[tense] But beneath the silence, something stirred.
[whisper] And it was getting closer.
```

---

## Best practices

- **Instructions set the floor, tags set the moments.** Use the instruction
  prompt to establish baseline delivery, then use inline tags only where the
  delivery needs to change
- **Don't over-tag.** Add tags only when the intended delivery changes or when
  a long passage needs the mood restated. Excessive tags make prosody sound
  fragmented
- **Tag placement matters.** Put the tag immediately before the word/phrase it
  should affect
- **Combine emotion + event:** `[nervous] [breathing] I don't know if I can do this`
- **The 86 tags are the supported set.** Free-form tags outside this set may
  be ignored — unlike Fish Audio S2, Qwen3-TTS works best with its known tag
  vocabulary
- **Multilingual support.** Instructions can be in any language; inline tags
  work across all supported languages
