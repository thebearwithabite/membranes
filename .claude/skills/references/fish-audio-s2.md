# Fish Audio S2 — Inline Tag Reference

Fish Audio S2 (and S2-Pro) uses **open-domain natural-language tags** in
`[square brackets]` for emotion and delivery control, plus `(parenthesized)`
paralanguage cues for vocal texture and timing. Tags can appear anywhere —
mid-sentence, between words, or at the start.

Over 15,000 unique tags are supported. Any descriptive phrase in brackets
works — from single keywords like `[laughs]` to full descriptions like
`[laughing nervously while trying to keep composure]`.

---

## Tag syntax

### Bracket tags — emotion and delivery

Place `[tag]` inline to direct the vocal performance:

```
[excited] I can't believe this is happening!
[whisper] Don't tell anyone, but [emphasis] I already knew.
```

### Parenthesized cues — paralanguage

Use `(cue)` for non-speech vocal events and timing:

```
(breath) Okay... (long-break) Let me think about this.
```

---

## Common bracket tags

### Emotion

`[excited]` `[angry]` `[sad]` `[surprised]` `[shocked]` `[delight]`
`[fearful]` `[nervous]` `[frustrated]` `[melancholy]` `[content]`
`[hopeful]` `[annoyed]` `[disgusted]` `[loving]` `[flirty]`

### Voice / volume

`[whisper]` `[low voice]` `[shouting]` `[screaming]` `[loud]`
`[low volume]` `[volume up]` `[volume down]`

### Expression

`[laughing]` `[chuckle]` `[sigh]` `[inhale]` `[exhale]` `[panting]`
`[tsk]` `[giggles]` `[sobbing]` `[groaning]` `[gasp]`

### Pacing

`[pause]` `[short pause]` `[emphasis]` `[slow]` `[fast]`
`[drawn out]` `[rushed]`

### Style

`[singing]` `[excited tone]` `[laughing tone]`
`[professional broadcast tone]` `[echo]`

### Pitch

`[pitch up]` `[pitch down]` `[high pitch]` `[low pitch]`

---

## Paralanguage cues (parentheses)

| Cue | Effect |
|---|---|
| `(break)` | Short pause |
| `(long-break)` | Extended pause |
| `(breath)` | Audible inhale |
| `(laugh)` | Inline laugh sound |
| `(cough)` | Cough sound |
| `(sigh)` | Sigh sound |
| `(lip-smacking)` | Lip-smacking sound |

---

## Example scripts

### Conversational with emotion shifts

```
[inhale] Okay... let me think about this.
[short pause]
I [emphasis] definitely knew the answer yesterday.
[exhale]
[sad] But now... I'm not so sure anymore.
```

### Character voice with mixed delivery

```
[flirty] Hey, why don't you come a little [emphasis] closer?
[giggles]
[slow] But seriously though...
[whisper] I have a secret to tell you.
```

### Narration with atmosphere

```
[low voice] The door creaked open.
(breath)
[nervous] [whisper] Is anyone there?
(long-break)
[shouting] WHO'S THERE?!
```

### Podcast / professional

```
[professional broadcast tone] Welcome to today's episode.
[pause]
[excited tone] We have an incredible story to share.
[emphasis] And you won't believe how it ends.
```

---

## Tips

- Tags are open-domain — any natural-language phrase in brackets works
- Combine bracket tags with paralanguage: `[nervous] (breath) Okay...`
- Use `[emphasis]` before a specific word for stress
- Descriptive tags work: `[speaking as if holding back tears]`
- Avoid stacking too many tags in a single phrase — let the model breathe
- For voice cloning, provide a ~10-second reference audio clip
- S2 achieves ~100ms time-to-first-audio on high-end hardware
- 80+ languages supported
